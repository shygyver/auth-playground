import { createMiddleware } from "hono/factory";

// 1. Extend Hono's Environment to type the variables we inject into the context
export type Env = {
  Variables: {
    clientDn: string;
    clientCert: string;
    clientCn: string;
  };
};

export const mtlsGuard = () => {
  return createMiddleware<Env>(async (c, next) => {
    const sslVerify = c.req.header("X-SSL-Client-Verify");
    const rawDn = c.req.header("X-SSL-Client-DN");
    const rawCert = c.req.header("X-SSL-Client-Cert");

    // 2. Fail fast if Nginx didn't successfully authenticate the client
    if (sslVerify !== "SUCCESS" || !rawDn || !rawCert) {
      return c.json({ error: "Unauthorized: Valid mTLS authentication required." }, 401);
    }

    // 3. Decode the certificate PEM string
    const decodedCert = decodeURIComponent(rawCert);

    // 4. Extract the Common Name (CN) from the DN string using a quick Regex
    // Example DN: /CN=test-developer-client/O=DevTeam
    const cnMatch = rawDn.match(/CN=([^/ ,]+)/);
    const clientCn = cnMatch ? cnMatch[1] : "Unknown";

    // 5. Inject the parsed details safely into the context
    c.set("clientDn", rawDn);
    c.set("clientCert", decodedCert);
    c.set("clientCn", clientCn);

    await next();
  });
};
