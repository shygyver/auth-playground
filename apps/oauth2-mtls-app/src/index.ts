import { mtlsGuard, type Env } from "./mtls-guard";
import { clientFlow, jwksAuthority } from "./oauth2/client-flow";
import { UnauthorizedClientError, UnsupportedGrantTypeError } from "@saurbit/oauth2";
import { Hono } from "hono";

const app = new Hono<Env>();

app.use("*", mtlsGuard());

app.get("/", async (c) => {
  return c.json({
    message: "Secure proxy authentication successful! mTLS babyyyyy!",
    verification: c.var.clientCn,
    subject: c.var.clientDn,
    // Provide the raw certificate text if your code processes Node:crypto or Forge
    certReceived: c.var.clientCert.substring(0, 40) + "...",
  });
});

app.get("/.well-known/jwks.json", async (c) => {
  return c.json(await jwksAuthority.getJwksEndpointResponse());
});

app.post(clientFlow.getTokenEndpoint(), async (c) => {
  const result = await clientFlow.hono().token(c);
  if (result.success) {
    return c.json(result.tokenResponse);
  }

  const error = result.error;
  console.error(error);
  if (error instanceof UnsupportedGrantTypeError || error instanceof UnauthorizedClientError) {
    return c.json({ error: error.errorCode, errorDescription: error.message }, 400);
  }
  return c.json({ error: "invalid_request" }, 400);
});

app.get("/api/protected-resource", clientFlow.hono().authorizeMiddleware(["content:read"]), (c) => {
  const clientApp = c.get("credentials")?.app;
  return c.json({
    message: `Hello, ${clientApp?.id}! You have accessed a protected resource.`,
  });
});

export default {
  port: 3000,
  fetch: app.fetch,
};
