import { jwksStore, rotationTimestampStore } from "./stores";
import { HonoOIDCAuthorizationCodeFlowBuilder } from "@saurbit/hono-oauth2";
import {
  AccessDeniedError,
  getOriginFromRequest,
  StrategyInsufficientScopeError,
  StrategyInternalError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from "@saurbit/oauth2";
import { JoseJwksAuthority, JwksRotator } from "@saurbit/oauth2-jwt";
import { Scalar } from "@scalar/hono-api-reference";
import { Hono } from "hono";
import { describeRoute, openAPIRouteHandler } from "hono-openapi";
import { cors } from "hono/cors";
import { html } from "hono/html";
import { HTTPException } from "hono/http-exception";

declare module "@saurbit/oauth2" {
  interface UserCredentials {
    id: string;
    email: string;
    fullName: string;
    username: string;
  }
}

// TODO: we might need issuer in request context for some operations (e.g. token verification) if we want to support multiple issuers in the future. For now we can hardcode it since this example only has one issuer.

// remove issuer hardcoding when we have a better way to determine it (e.g. from request context or configuration)
// const ISSUER = process.env.ISSUER || "http://localhost:3001";
const DISCOVERY_ENDPOINT_PATH = "/.well-known/openid-configuration";

const jwksAuthority = new JoseJwksAuthority(jwksStore, 8.64e6); // 100-day key lifetime

//await jwksAuthority.generateKeyPair()

const jwksRotator = new JwksRotator({
  keyGenerator: jwksAuthority,
  rotationTimestampStore: rotationTimestampStore,
  rotationIntervalMs: 7.884e9, // 91 days
});

const CLIENT: {
  id: string;
  secret: string;
  grants: string[];
  redirectUris: string[];
  scopes: string[];
} = {
  id: "example-client",
  secret: "example-secret",
  grants: ["authorization_code"],
  redirectUris: [],
  scopes: ["openid", "profile", "email", "content:read", "content:write"],
};

const USER = {
  id: "user123",
  fullName: "John Doe",
  email: "user@example.com",
  username: "user",
  password: "crossterm",
};

// Short-lived authorization code storage
const codeStorage: Record<
  string,
  {
    clientId: string;
    scope: string[];
    userId: string;
    expiresAt: number;
    codeChallenge?: string;
    nonce?: string;
  }
> = {};

const flow = HonoOIDCAuthorizationCodeFlowBuilder.create({
  parseAuthorizationEndpointData: async (c) => {
    const formData = await c.req.formData();
    const username = formData.get("username");
    const password = formData.get("password");

    return {
      username: typeof username === "string" ? username : undefined,
      password: typeof password === "string" ? password : undefined,
    };
  },
})
  .setSecuritySchemeName("openidConnect")
  .setScopes({
    openid: "OpenID Connect scope",
    profile: "Access to your profile information",
    email: "Access to your email address",
    "content:read": "Access to read content",
    "content:write": "Access to write content",
  })
  .setDescription("Example OpenID Connect Authorization Code Flow")
  .setDiscoveryUrl(`${DISCOVERY_ENDPOINT_PATH}`)
  .setJwksEndpoint("/.well-known/jwks.json")
  .setAuthorizationEndpoint("/authorize")
  .setTokenEndpoint("/token")
  .setUserInfoEndpoint("/userinfo")
  .clientSecretPostAuthenticationMethod()
  .noneAuthenticationMethod()
  .setAccessTokenLifetime(3600)
  .setOpenIdConfiguration({
    claims_supported: ["sub", "aud", "iss", "exp", "iat", "nbf", "name", "email", "username"],
  })
  .getClientForAuthentication((data) => {
    if (
      data.clientId === CLIENT.id &&
      (data.redirectUri === `${data.origin}/scalar` ||
        CLIENT.redirectUris.includes(data.redirectUri))
    ) {
      return {
        id: CLIENT.id,
        grants: CLIENT.grants,
        redirectUris: CLIENT.redirectUris,
        scopes: CLIENT.scopes,
      };
    }
  })
  .getUserForAuthentication((_ctxt, parsedData) => {
    if (parsedData.username === USER.username && parsedData.password === USER.password) {
      return {
        type: "authenticated",
        user: {
          id: USER.id,
          fullName: USER.fullName,
          email: USER.email,
          username: USER.username,
        },
      };
    }
  })
  .generateAuthorizationCode((grantContext, user) => {
    if (!user.id) {
      return undefined;
    }
    const code = crypto.randomUUID();
    codeStorage[code] = {
      clientId: grantContext.client.id,
      scope: grantContext.scope,
      userId: `${user.id}`,
      expiresAt: Date.now() + 60000,
      codeChallenge: grantContext.codeChallenge,
      nonce: grantContext.nonce,
    };
    return { type: "code", code };
  })
  .getClient(async (tokenRequest) => {
    if (
      tokenRequest.grantType === "authorization_code" &&
      tokenRequest.clientId === CLIENT.id &&
      tokenRequest.code
    ) {
      const codeData = codeStorage[tokenRequest.code];
      if (!codeData) return undefined;
      if (codeData.clientId !== tokenRequest.clientId) return undefined;
      if (codeData.expiresAt < Date.now()) {
        delete codeStorage[tokenRequest.code];
        return undefined;
      }

      if (tokenRequest.clientSecret) {
        // Private client — verify the secret
        if (tokenRequest.clientSecret !== CLIENT.secret) return undefined;
      } else if (tokenRequest.codeVerifier && codeData.codeChallenge) {
        // Public client — verify PKCE code_verifier against the stored code_challenge
        const data = new TextEncoder().encode(tokenRequest.codeVerifier);
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        const hashArray = new Uint8Array(hashBuffer);
        const base64url = btoa(String.fromCharCode(...hashArray))
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");
        if (base64url !== codeData.codeChallenge) return undefined;
      } else {
        return undefined;
      }

      return {
        id: CLIENT.id,
        grants: CLIENT.grants,
        redirectUris: CLIENT.redirectUris,
        scopes: CLIENT.scopes,
        metadata: {
          accessScope: codeData.scope,
          userId: codeData.userId,
          username: USER.username,
          userEmail: USER.email,
          userFullName: USER.fullName,
          nonce: codeData.nonce,
        },
      };
    }
  })
  .generateAccessToken(async (grantContext) => {
    const accessScope = Array.isArray(grantContext.client.metadata?.accessScope)
      ? grantContext.client.metadata.accessScope
      : [];

    const registeredClaims = {
      exp: Math.floor(Date.now() / 1000) + grantContext.accessTokenLifetime,
      iat: Math.floor(Date.now() / 1000),
      nbf: Math.floor(Date.now() / 1000),
      iss: grantContext.origin,
      aud: grantContext.client.id,
      jti: crypto.randomUUID(),
      sub: `${grantContext.client.metadata?.userId}`,
    };

    const { token: accessToken } = await jwksAuthority.sign({
      scope: accessScope.join(" "),
      ...registeredClaims,
    });

    const { token: idToken } = await jwksAuthority.sign({
      username: `${grantContext.client.metadata?.username}`,
      name: accessScope.includes("profile")
        ? `${grantContext.client.metadata?.userFullName}`
        : undefined,
      email: accessScope.includes("email")
        ? `${grantContext.client.metadata?.userEmail}`
        : undefined,
      nonce: grantContext.client.metadata?.nonce
        ? `${grantContext.client.metadata?.nonce}`
        : undefined,
      ...registeredClaims,
    });

    return {
      accessToken,
      scope: accessScope,
      idToken,
    };
  })
  .tokenVerifier(async (_c, { token }) => {
    try {
      const payload = await jwksAuthority.verify(token);
      if (payload && payload.sub === USER.id && typeof payload.scope === "string") {
        return {
          isValid: true,
          credentials: {
            user: {
              id: USER.id,
              fullName: USER.fullName,
              email: USER.email,
              username: USER.username,
            },
            scope: payload.scope.split(" "),
          },
        };
      }
    } catch (error) {
      console.error("Token verification error:", {
        error: error instanceof Error ? { name: error.name, message: error.message } : error,
      });
    }
    return { isValid: false };
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

const app = new Hono();

app.use("/*", cors());

app.get(DISCOVERY_ENDPOINT_PATH, (c) => {
  const config = flow.getDiscoveryConfiguration(c.req.raw);
  return c.json(config);
});

app.get(flow.getJwksEndpoint(), async (c) => {
  return c.json(await jwksAuthority.getJwksEndpointResponse());
});

app.get(flow.getAuthorizationEndpoint(), async (c) => {
  const result = await flow.hono().initiateAuthorization(c);
  if (result.success) {
    return c.html(HtmlFormContent({ usernameField: "username", passwordField: "password" }));
  }
  return c.json({ error: "invalid_request" }, 400);
});

app.post(flow.getAuthorizationEndpoint(), async (c) => {
  try {
    const result = await flow.hono().processAuthorization(c);

    if (result.type === "error") {
      const error = result.error;
      if (result.redirectable) {
        const qs = [
          `error=${encodeURIComponent(error instanceof AccessDeniedError ? error.errorCode : "invalid_request")}`,
          `error_description=${encodeURIComponent(
            error instanceof AccessDeniedError ? error.message : "Invalid request"
          )}`,
          result.state ? `state=${encodeURIComponent(result.state)}` : null,
        ]
          .filter(Boolean)
          .join("&");
        return c.redirect(`${result.redirectUri}?${qs}`);
      }
      return c.html(
        HtmlFormContent({
          usernameField: "username",
          passwordField: "password",
          errorMessage: error.message,
        }),
        400
      );
    }

    if (result.type === "code") {
      const {
        code,
        context: { state, redirectUri },
      } = result.authorizationCodeResponse;
      const searchParams = new URLSearchParams();
      searchParams.set("code", code);
      if (state) searchParams.set("state", state);
      return c.redirect(`${redirectUri}?${searchParams.toString()}`);
    }

    if (result.type === "unauthenticated") {
      return c.html(
        HtmlFormContent({
          usernameField: "username",
          passwordField: "password",
          errorMessage: result.message || "Authentication failed. Please try again.",
        }),
        400
      );
    }
  } catch (error) {
    console.error("Unexpected error at authorization endpoint:", {
      error: error instanceof Error ? { name: error.name, message: error.message } : error,
    });
    return c.html(
      HtmlFormContent({
        usernameField: "username",
        passwordField: "password",
        errorMessage: "An unexpected error occurred. Please try again later.",
      }),
      500
    );
  }
});

app.post(flow.getTokenEndpoint(), async (c) => {
  const result = await flow.hono().token(c);
  if (result.success) {
    return c.json(result.tokenResponse);
  }
  const error = result.error;
  if (error instanceof UnsupportedGrantTypeError || error instanceof UnauthorizedClientError) {
    return c.json({ error: error.errorCode, errorDescription: error.message }, 400);
  }
  return c.json({ error: "invalid_request" }, 400);
});

app.get(
  flow.getUserInfoEndpoint() || "/userinfo",
  flow.hono().authorizeMiddleware(["openid"]),
  describeRoute({
    summary: "User Info",
    description: "Returns claims about the authenticated end-user.",
    security: [flow.toOpenAPIPathItem(["openid"])],
    responses: {
      200: {
        description: "User claims.",
        content: {
          "application/json": {
            example: {
              sub: "user123",
              username: "user",
              name: "John Doe",
              email: "user@example.com",
            },
          },
        },
      },
    },
  }),
  (c) => {
    const credentials = c.get("credentials");
    const user = credentials?.user;
    const scope = credentials?.scope || [];
    return c.json({
      sub: user?.id,
      username: user?.username,
      name: scope.includes("profile") ? user?.fullName : undefined,
      email: scope.includes("email") ? user?.email : undefined,
    });
  }
);

app.get(
  "/protected-resource",
  flow.hono().authorizeMiddleware(["content:read"]),
  describeRoute({
    summary: "Protected Resource",
    description: "Requires a valid access token with the 'content:read' scope.",
    security: [flow.toOpenAPIPathItem(["content:read"])],
    responses: {
      200: {
        description: "Protected resource data.",
        content: {
          "application/json": {
            example: {
              message: "Hello, John Doe! You have accessed a protected resource.",
            },
          },
        },
      },
      401: { description: "Unauthorized." },
      403: { description: "Forbidden — insufficient scope." },
    },
  }),
  (c) => {
    const user = c.get("credentials")?.user;
    return c.json({
      message: `Hello, ${user?.fullName}! You have accessed a protected resource.`,
    });
  }
);

app.get("/openapi.json", async (c, n) => {
  const issuer = getOriginFromRequest(c.req.raw);

  const schemes = flow.toOpenAPISecurityScheme();

  for (const schemeName in schemes) {
    if (schemeName === "openidConnect") {
      schemes[schemeName].openIdConnectUrl = `${issuer}${schemes[schemeName].openIdConnectUrl}`;
      break;
    }
  }

  return await openAPIRouteHandler(app, {
    documentation: {
      info: { title: "Auth Server API", version: "0.1.0" },
      components: {
        securitySchemes: { ...schemes },
      },
    },
  })(c, n);
});

app.get(
  "/scalar",
  Scalar({ url: "/openapi.json", theme: "bluePlanet", showDeveloperTools: "localhost" })
);

await jwksRotator.checkAndRotateKeys();

setInterval(async () => {
  await jwksRotator.checkAndRotateKeys();
}, 3.6e6);

function HtmlFormContent(props: {
  errorMessage?: string;
  usernameField: string;
  passwordField: string;
}) {
  return html` <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <title>Sign in</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      </head>
      <body>
        <h1>Sign in</h1>
        ${props.errorMessage ? html`<p style="color:red">${props.errorMessage}</p>` : ""}
        <form method="POST">
          <label for="${props.usernameField}">${props.usernameField}</label>
          <input
            id="${props.usernameField}"
            name="${props.usernameField}"
            type="text"
            autocomplete="username"
            required
          />
          <label for="${props.passwordField}">${props.passwordField}</label>
          <input
            id="${props.passwordField}"
            name="${props.passwordField}"
            type="password"
            autocomplete="current-password"
            required
          />
          <button type="submit">Sign in</button>
        </form>
      </body>
    </html>`;
}

export default {
  port: 3001,
  fetch: app.fetch,
};
