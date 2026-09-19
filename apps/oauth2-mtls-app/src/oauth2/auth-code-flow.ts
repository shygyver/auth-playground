import {
  deleteCode,
  deleteRefreshToken,
  deleteSession,
  findClientById,
  findClientBySubjectDnAndId,
  findUserByCredentials,
  findUserById,
  getCodeData,
  getRefreshTokenData,
  getSessionData,
  storeCode,
  storeRefreshToken,
} from "../data";
import { CertificateBoundValidationResponse } from "./mtls_certificate_bound_token_type";
import { TlsClientAuthMethod } from "./tls_client_auth";
import { HonoAuthorizationCodeFlowBuilder } from "@saurbit/hono-oauth2";
import { StrategyInsufficientScopeError, StrategyInternalError } from "@saurbit/oauth2";
import { createInMemoryKeyStore, JoseJwksAuthority } from "@saurbit/oauth2-jwt";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { HTTPException } from "hono/http-exception";

declare module "@saurbit/oauth2" {
  interface UserCredentials {
    id: string;
    username: string;
    email: string;
    fullName: string;
  }
}

const jwksStore = createInMemoryKeyStore();

// Signs JWTs and exposes the public JWKS endpoint
export const jwksAuthority = new JoseJwksAuthority(jwksStore, 8.64e6); // 100-day key lifetime

const tlsClientAuthMethod = new TlsClientAuthMethod({
  certHeaderName: "x-ssl-client-cert",
  certDnHeaderName: "x-ssl-client-dn",
  certExpireHeaderName: "x-ssl-client-expire",
  validateClientSubject: async (clientId, headers) => {
    // Implement your client certificate validation logic here
    // For example, you might check the certificate against a database record
    // or perform cryptographic verification.
    const { certDn, certExpire } = headers;
    if (!certDn) return false;
    const client = await findClientBySubjectDnAndId(certDn ?? "", clientId);
    if (!client) return false;
    if (certExpire && Date.now() > new Date(certExpire).getTime()) return false;
    return true; // Return true if the certificate is valid, false otherwise
  },
});

const certificateBoundTokenType = tlsClientAuthMethod.createCertificateBoundTokenType(
  async (token) => {
    const refreshTokenData = await getRefreshTokenData(token);
    if (refreshTokenData) {
      return refreshTokenData;
    }
    return await jwksAuthority.verify(token);
  },
  true // Enable bound refresh token
);

export const authCodeFlow = new HonoAuthorizationCodeFlowBuilder({
  securitySchemeName: "authCodeMtls",
  scopes: {
    offline_access: "Request refresh token for offline access",
    profile: "Access to your profile information",
    email: "Access to your email address",
    "content:read": "Read access to content",
    "content:write": "Write access to content",
  },
  authorizationEndpoint: "/authorize",
  tokenEndpoint: "/token",
  accessTokenLifetime: 3600, // 1 hour in seconds
  parseAuthorizationEndpointData: async (c) => {
    let formData: FormData | undefined = undefined;
    if (c.req.method === "POST") {
      try {
        formData = await c.req.formData();
      } catch (error) {
        console.error("Error parsing form data:", {
          error: error instanceof Error ? { name: error.name, message: error.message } : error,
        });
      }
    }
    const username = formData?.get("username");
    const password = formData?.get("password");
    const consent = formData?.get("consent");

    const sessionCookie = getCookie(c, "session");

    return {
      username: typeof username === "string" ? username : undefined,
      password: typeof password === "string" ? password : undefined,
      consent: consent === "allow" || consent === "deny" ? consent : undefined,
      sessionCookie,
    };
  },
})
  // Register your custom mTLS authenticator
  .addClientAuthenticationMethod(tlsClientAuthMethod)
  // Cleanly delegate token validation responsibility to your class instance
  .setTokenType(certificateBoundTokenType)
  .getClientForAuthentication(async (data) => {
    const client = await findClientById(data.clientId);
    if (!client) {
      return undefined;
    }
    if (
      data.redirectUri === `${data.origin}/scalar` ||
      client.redirectUris.includes(data.redirectUri)
    ) {
      return {
        id: client.clientId,
        grants: client.grantTypes,
        redirectUris: client.redirectUris,
        scopes: client.allowedScopes,
      };
    }
  })
  // enhanced user authentication to check for existing session and consent before validating credentials
  .getUserForAuthentication(async (_ctxt, parsedData) => {
    // Check for existing session first
    if (parsedData.sessionCookie) {
      const session = await getSessionData(parsedData.sessionCookie);
      if (session) {
        if (session.expiresAt <= Date.now()) {
          // Session expired, clean up
          await deleteSession(parsedData.sessionCookie);
        } else if (session.expiresAt > Date.now()) {
          const user = await findUserById(session.userId);
          if (user) {
            return {
              type: "authenticated",
              user: {
                id: user.id,
                fullName: user.fullName,
                email: user.email,
                username: user.username,
                consentStatus: parsedData.consent, // carry the consent decision  forward
              },
            };
          }
        }
      }
    }

    if (parsedData.username && parsedData.password) {
      const user = await findUserByCredentials(parsedData.username, parsedData.password);
      // If no valid session, check credentials
      if (user) {
        return {
          type: "authenticated",
          user: {
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            username: user.username,
          },
        };
      }
    }
  })
  // generate authorization code based on user consent status, and include consent status in the user object for downstream processing
  .generateAuthorizationCode(async (grantContext, user) => {
    if (!user.id) {
      return undefined;
    }

    if (user.consentStatus === "deny") {
      return {
        type: "deny",
        message: "The user has denied consent for this application.",
      };
    }

    if (user.consentStatus === "allow") {
      const code = crypto.randomUUID();
      await storeCode(code, {
        clientId: grantContext.client.id,
        scope: grantContext.scope,
        userId: `${user.id}`,
        expiresAt: Date.now() + 60000,
        codeChallenge: grantContext.codeChallenge,
      });
      return { type: "code", code };
    }

    return {
      type: "continue",
    };
  })
  // Handle validation inside your client retriever
  .getClient(async (tokenRequest) => {
    // 1. Fetch client details from database
    const client = await findClientById(tokenRequest.clientId);
    if (!client) return undefined;

    // 2. Enforce mTLS path if it matches the client configuration
    const registeredThumbprint = client.registeredCertificate;
    if (typeof registeredThumbprint !== "string") {
      return undefined; // Reject if the registered certificate or thumbprint is not a string
    }

    const incomingPem = tokenRequest.clientSecret; // This holds our cert string from extractClientCredentials
    if (!incomingPem) return undefined;
    const { x5tS256: incomingThumbprint } =
      await certificateBoundTokenType.computeThumbprint(incomingPem);

    // 3. Cryptographically validate the incoming cert matches your target record.
    // Depending on your setup, you might compare standard SHA-256 thumbprints
    // or check the certificate chain validity.
    const isValidCert = incomingThumbprint === registeredThumbprint;

    if (!isValidCert) {
      return undefined; // Rejects authorization
    }

    if (
      tokenRequest.grantType === "authorization_code" &&
      tokenRequest.clientId === client.clientId &&
      tokenRequest.code
    ) {
      const codeData = await getCodeData(tokenRequest.code);
      if (!codeData) return undefined;
      if (codeData.clientId !== tokenRequest.clientId) return undefined;
      if (codeData.expiresAt < Date.now()) {
        await deleteCode(tokenRequest.code);
        return undefined;
      }

      if (!tokenRequest.codeVerifier || !codeData.codeChallenge) {
        return undefined; // Reject if PKCE parameters are missing
      }

      // verify PKCE code_verifier against the stored code_challenge
      const data = new TextEncoder().encode(tokenRequest.codeVerifier);
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const hashArray = new Uint8Array(hashBuffer);
      const base64url = btoa(String.fromCharCode(...hashArray))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
      if (base64url !== codeData.codeChallenge) return undefined;

      const user = await findUserById(codeData.userId);
      if (!user) return undefined;

      return {
        id: client.clientId,
        grants: client.grantTypes,
        redirectUris: client.redirectUris,
        scopes: client.allowedScopes,
        metadata: {
          accessScope: codeData.scope,
          userId: codeData.userId,
          username: user.username,
          userEmail: user.email,
          userFullName: user.fullName,
          nonce: codeData.nonce,
          incomingThumbprint: incomingThumbprint,
        },
      };
    }

    // new: handle refresh token grant type by
    // validating the refresh token and
    // returning the associated client and user information for access token generation
    if (
      tokenRequest.grantType === "refresh_token" &&
      tokenRequest.clientId === client.clientId &&
      client.grantTypes.includes("refresh_token")
    ) {
      const refreshTokenData = await getRefreshTokenData(tokenRequest.refreshToken);
      // validate the refresh token and its association with the client
      if (!refreshTokenData)
        throw new HTTPException(400, {
          res: new Response(
            JSON.stringify({ error: "invalid_grant", error_description: "Invalid refresh token" }),
            {
              headers: { "Content-Type": "application/json" },
            }
          ),
        });
      if (refreshTokenData.clientId !== tokenRequest.clientId)
        throw new HTTPException(400, {
          res: new Response(
            JSON.stringify({
              error: "invalid_grant",
              error_description: "Invalid client for refresh token",
            }),
            {
              headers: { "Content-Type": "application/json" },
            }
          ),
        });

      const user = await findUserById(refreshTokenData.userId);
      if (!user)
        throw new HTTPException(400, {
          res: new Response(
            JSON.stringify({
              error: "invalid_grant",
              error_description: "Invalid user for refresh token",
            }),
            {
              headers: { "Content-Type": "application/json" },
            }
          ),
        });

      // for security, remove the used refresh token to prevent reuse (rotate on each use)
      await deleteRefreshToken(tokenRequest.refreshToken);

      // check if the refresh token has expired
      if (refreshTokenData.expiresAt < Date.now()) {
        throw new HTTPException(400, {
          res: new Response(
            JSON.stringify({
              error: "invalid_grant",
              error_description: "Refresh token has expired",
            }),
            {
              headers: { "Content-Type": "application/json" },
            }
          ),
        });
      }

      // determine the scope for the new access token based on the original scope of the refresh token and any requested scope in the token request
      const requestedScope = Array.isArray(tokenRequest.scope) ? tokenRequest.scope : [];

      const accessScope = requestedScope.length
        ? refreshTokenData.scope.filter((s) => requestedScope.includes(s))
        : refreshTokenData.scope;

      return {
        id: client.clientId,
        grants: client.grantTypes,
        redirectUris: client.redirectUris,
        scopes: client.allowedScopes,
        metadata: {
          accessScope,
          userId: refreshTokenData.userId,
          username: user.username,
          userEmail: user.email,
          userFullName: user.fullName,
          incomingThumbprint: incomingThumbprint,
        },
      };
    }
  })
  .generateAccessToken(async (grantContext) => {
    // Look back at the request to find the certificate
    const thumbprint = grantContext.client.metadata?.incomingThumbprint;

    if (typeof thumbprint !== "string") {
      return undefined; // Reject if the client certificate thumbprint is not available
    }

    const accessScope = Array.isArray(grantContext.client.metadata?.accessScope)
      ? grantContext.client.metadata.accessScope
      : [];

    const registeredClaims = await certificateBoundTokenType.applyBinding(
      {
        exp: Math.floor(Date.now() / 1000) + grantContext.accessTokenLifetime,
        iat: Math.floor(Date.now() / 1000),
        nbf: Math.floor(Date.now() / 1000),
        iss: grantContext.origin,
        aud: grantContext.client.id,
        jti: crypto.randomUUID(),
        sub: `${grantContext.client.metadata?.userId}`,
      },
      thumbprint
    );

    const { token: accessToken } = await jwksAuthority.sign({
      scope: accessScope.join(" "),
      ...registeredClaims,
    });

    // new: generate the refresh token if the "offline_access" scope was requested,
    // and store it in the refresh token storage with an expiration time
    const refreshToken = (() => {
      if (accessScope.includes("offline_access")) {
        return crypto.randomUUID();
      }
      return undefined;
    })();
    if (refreshToken) {
      await storeRefreshToken(refreshToken, {
        clientId: grantContext.client.id,
        userId: `${grantContext.client.metadata?.userId}`,
        scope: accessScope,
        expiresAt: Date.now() + 30 * 24 * 3600 * 1000, // 30 days
        ...(await certificateBoundTokenType.applyBinding({}, thumbprint)),
      });
    }

    // changed: return the refresh token in the token response
    return {
      accessToken,
      scope: accessScope,
      refreshToken,
    };
  })
  // new: generate access token from refresh token, reusing the same claims structure and signing method as the initial access token
  .generateAccessTokenFromRefreshToken(async (grantContext) => {
    // Look back at the request to find the certificate
    const thumbprint = grantContext.client.metadata?.incomingThumbprint;

    if (typeof thumbprint !== "string") {
      return undefined; // Reject if the client certificate thumbprint is not available
    }

    const accessScope = Array.isArray(grantContext.client.metadata?.accessScope)
      ? grantContext.client.metadata.accessScope
      : [];

    const registeredClaims = await certificateBoundTokenType.applyBinding(
      {
        exp: Math.floor(Date.now() / 1000) + grantContext.accessTokenLifetime,
        iat: Math.floor(Date.now() / 1000),
        nbf: Math.floor(Date.now() / 1000),
        iss: grantContext.origin,
        aud: grantContext.client.id,
        jti: crypto.randomUUID(),
        sub: `${grantContext.client.metadata?.userId}`,
      },
      thumbprint
    );

    const { token: accessToken } = await jwksAuthority.sign({
      scope: accessScope.join(" "),
      ...registeredClaims,
    });

    // new: generate the refresh token if the "offline_access" scope was requested,
    // and store it in the refresh token storage with an expiration time
    const refreshToken = (() => {
      if (accessScope.includes("offline_access")) {
        return crypto.randomUUID();
      }
      return undefined;
    })();
    if (refreshToken) {
      await storeRefreshToken(refreshToken, {
        clientId: grantContext.client.id,
        userId: `${grantContext.client.metadata?.userId}`,
        scope: accessScope,
        expiresAt: Date.now() + 30 * 24 * 3600 * 1000, // 30 days
        ...(await certificateBoundTokenType.applyBinding({}, thumbprint)),
      });
    }

    // changed: return the refresh token in the token response
    return {
      accessToken,
      scope: accessScope,
      refreshToken,
    };
  })
  .tokenVerifier(async (_c, { tokenTypeValidation }) => {
    try {
      // 1. Safely extract the pre-verified payload from your custom type
      const validationResult = tokenTypeValidation as CertificateBoundValidationResponse;
      const payload = validationResult?.data?.mtlsPayload;

      // 2. Enforce basic presence of required identity fields
      if (
        !payload ||
        typeof payload.scope !== "string" ||
        !payload.sub ||
        typeof payload.aud !== "string"
      ) {
        return { isValid: false, message: "Malformed or missing token payload context." };
      }

      // 3. Look up the client and user record to verify their current operational state
      const user = await findUserById(payload.sub);
      const client = await findClientById(payload.aud);

      // If the client or user was deleted or disabled in the DB post-issuance, reject immediately
      if (!client) {
        return { isValid: false, message: "Client record not found or inactive." };
      }
      if (!user) {
        return { isValid: false, message: "User record not found or inactive." };
      }

      // 4. Return successful credentials mapped cleanly to the app context
      return {
        isValid: true,
        credentials: {
          user: {
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            username: user.username,
          },
          // Split the space-delimited OAuth2 scope string into a clean array
          scope: payload.scope.split(" "),
        },
      };
    } catch (error) {
      // CRITICAL: Do not completely swallow runtime errors. Log them for visibility!
      console.error("Token verification error:", {
        error: error instanceof Error ? { name: error.name, message: error.message } : error,
      });

      // Fall through to reject the request safely
      return { isValid: false, message: "Internal server error verifying token credentials." };
    }
  })
  .failedAuthorizationAction((_, error) => {
    console.error("Authorization failed:", { error: error.name, message: error.message });

    if (error instanceof StrategyInternalError) {
      throw new HTTPException(500, { message: "Internal server error" });
    }
    if (error instanceof StrategyInsufficientScopeError) {
      throw new HTTPException(403, { message: "Forbidden" });
    }
    throw new HTTPException(401, { message: "Unauthorized" });
  })
  .build();
