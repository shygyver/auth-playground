/**
In modern production environments, the choice of reverse proxy or API gateway depends heavily on your infrastructure style (cloud-native containers, traditional VMs, or edge networks).
The most widely used options for handling mTLS termination and certificate header forwarding include:

* NGINX: The industry-standard web server and reverse proxy, dominant in Docker/Kubernetes configurations.
* Envoy: The cloud-native proxy that powers modern service meshes (like Istio) and popular API gateways (like Gloo Edge or Emissary-ingress).
* Traefik: A highly popular, cloud-native dynamic reverse proxy built specifically for container deployments.
* HAProxy: A high-performance load balancer favored in bare-metal, high-throughput financial setups.
* Cloud-Native Gateways (AWS ALB / Cloudflare): Managed infrastructure services that handle TLS termination completely off-box.

To make your @saurbit/oauth2 flow work, the proxy must be configured to do two things:

   1. Enable Mutual TLS: Set client verification to optional/required so the handshake asks for the client cert.
   2. Sanitize and Inject the Header: Strip any incoming x-ssl-client-cert headers from the open internet (to prevent spoofing attacks) and overwrite it with the verified PEM string before routing the request downstream to your application.
 */
import { findClientById, findClientBySubjectDnAndId } from "../data";
import {
  MtlsCertificateBoundTokenType,
  CertificateBoundValidationResponse,
} from "./mtls_certificate_bound_token_type";
import { TlsClientAuthMethod } from "./tls_client_auth";
import { HonoClientCredentialsFlowBuilder } from "@saurbit/hono-oauth2";
import { StrategyInsufficientScopeError, StrategyInternalError } from "@saurbit/oauth2";
import { createInMemoryKeyStore, JoseJwksAuthority } from "@saurbit/oauth2-jwt";
import { HTTPException } from "hono/http-exception";

declare module "@saurbit/oauth2" {
  interface AppCredentials {
    id: string;
  }
}

const jwksStore = createInMemoryKeyStore();

// Signs JWTs and exposes the public JWKS endpoint
export const jwksAuthority = new JoseJwksAuthority(jwksStore, 8.64e6); // 100-day key lifetime
const mtlsTokenType = new MtlsCertificateBoundTokenType(
  async (token) => await jwksAuthority.verify(token),
  "x-ssl-client-cert"
);

const tlsClientAuthMethod = new TlsClientAuthMethod({
  certHeaderName: "x-ssl-client-cert",
  certDnHeaderName: "x-ssl-client-cert-dn",
  certExpireHeaderName: "x-ssl-client-cert-expire",
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

// OAuth2 Flow
export const clientFlow = new HonoClientCredentialsFlowBuilder({
  securitySchemeName: "clientCredentialsMtls",
  scopes: {
    "content:read": "Read access to content",
    "content:write": "Write access to content",
  },
  tokenEndpoint: "/token",
  accessTokenLifetime: 600, // 10 minutes in seconds
})
  // Register your custom mTLS authenticator
  .addClientAuthenticationMethod(tlsClientAuthMethod)

  // Cleanly delegate token validation responsibility to your class instance
  .setTokenType(mtlsTokenType)

  // Handle validation inside your client retriever
  .getClient(async ({ clientId, clientSecret, scope }) => {
    // 1. Fetch client details from database
    const client = await findClientById(clientId);
    if (!client) return undefined;

    // 2. Enforce mTLS path if it matches the client configuration
    const registeredThumbprint = client.registeredCertificate;
    if (typeof registeredThumbprint !== "string") {
      return undefined; // Reject if the registered certificate or thumbprint is not a string
    }

    const incomingPem = clientSecret; // This holds our cert string from extractClientCredentials
    const incomingThumbprint = await mtlsTokenType.calculateX5tS256(incomingPem);

    // 3. Cryptographically validate the incoming cert matches your target record.
    // Depending on your setup, you might compare standard SHA-256 thumbprints
    // or check the certificate chain validity.
    const isValidCert = incomingThumbprint === registeredThumbprint;

    if (!isValidCert) {
      return undefined; // Rejects authorization
    }

    const requestedScope = Array.isArray(scope) ? scope : [];
    const accessScope = requestedScope.length
      ? client.allowedScopes.filter((s) => requestedScope.includes(s))
      : client.allowedScopes;

    return {
      grants: client.grantTypes,
      id: client.clientId,
      scopes: client.allowedScopes,
      redirectUris: client.redirectUris,
      metadata: {
        accessScope: accessScope,
        incomingThumbprint: incomingThumbprint,
      },
    };
  })
  .generateAccessToken(async ({ client }) => {
    // Look back at the request to find the certificate
    const thumbprint = client.metadata?.incomingThumbprint;

    if (typeof thumbprint !== "string") {
      return undefined; // Reject if the client certificate thumbprint is not available
    }

    const accessScope = Array.isArray(client.metadata?.accessScope)
      ? client.metadata.accessScope
      : [];

    // Bake the 'cnf' thumbprint claim directly into the token structure
    const claims = mtlsTokenType.addThumbprintToCnfClaim(
      {
        sub: client.id,
        scope: accessScope.join(" "),
      },
      thumbprint
    );

    // Sign the JWT with the updated claims containing the mTLS thumbprint
    const { token } = await jwksAuthority.sign(claims);

    return token;
  })
  // SENDER CONSTRAINING HAPPENS HERE ON EVERY API REQUEST
  .tokenVerifier(async (_ctxt, { token: _token, tokenTypeValidation }) => {
    try {
      // 1. Safely extract the pre-verified payload from your custom type
      const validationResult = tokenTypeValidation as CertificateBoundValidationResponse;
      const payload = validationResult?.data?.mtlsPayload;

      // 2. Enforce basic presence of required identity fields
      if (!payload || typeof payload.scope !== "string" || !payload.sub) {
        return { isValid: false, message: "Malformed or missing token payload context." };
      }

      // 3. Look up the client record to verify their current operational state
      const client = await findClientById(payload.sub);

      // If the client was deleted or disabled in the DB post-issuance, reject immediately
      if (!client) {
        return { isValid: false, message: "Client record not found or inactive." };
      }

      // 4. Return successful credentials mapped cleanly to the app context
      return {
        isValid: true,
        credentials: {
          app: {
            id: client.clientId,
          },
          // Split the space-delimited OAuth2 scope string into a clean array
          scope: payload.scope.split(" "),
        },
      };
    } catch (error) {
      // CRITICAL: Do not completely swallow runtime errors. Log them for visibility!
      console.error("Database or lookup failure during token verification:", error);

      // Fall through to reject the request safely
      return { isValid: false, message: "Internal server error verifying token credentials." };
    }
  })
  .failedAuthorizationAction((_, error) => {
    console.error("Failed authorization action triggered:", error);
    if (error instanceof StrategyInternalError) {
      throw new HTTPException(500, { message: "Internal server error" });
    }
    if (error instanceof StrategyInsufficientScopeError) {
      throw new HTTPException(403, { message: "Forbidden" });
    }
    throw new HTTPException(401, { message: "Unauthorized" });
  })
  .build();
