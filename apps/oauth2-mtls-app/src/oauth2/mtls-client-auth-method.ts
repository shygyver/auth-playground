import type {
  ClientAuthMethod,
  ClientAuthMethodResponse,
  TokenEndpointAuthMethod,
} from "@saurbit/oauth2";

export class MtlsClientAuthMethod implements ClientAuthMethod {
  // RFC 8705 officially registers this name
  readonly method: TokenEndpointAuthMethod = "tls_client_auth" as TokenEndpointAuthMethod;

  // mTLS relies on private key possession, not a symmetric client secret
  readonly secretIsOptional = true;

  constructor(
    // Customize the header key based on your reverse proxy config
    private readonly certHeaderName: string = "x-ssl-client-cert"
  ) {}

  async extractClientCredentials(request: Request): Promise<ClientAuthMethodResponse> {
    // 1. mTLS authentication must only happen on POST requests to the token endpoint
    if (request.method !== "POST") {
      return { hasAuthMethod: false };
    }

    // 2. Look for the TLS client certificate forwarded by your reverse proxy
    const clientCertPem = request.headers.get(this.certHeaderName);
    if (!clientCertPem) {
      return { hasAuthMethod: false };
    }

    try {
      // 3. RFC 8705 states the client MUST include its 'client_id' in the request body
      // We parse the urlencoded body to extract it.
      const contentType = request.headers.get("content-type") || "";
      if (!contentType.includes("application/x-www-form-urlencoded")) {
        return { hasAuthMethod: false };
      }

      // Clone the request because reading body consumes the stream
      const clonedRequest = request.clone();
      const formData = await clonedRequest.formData();
      const clientId = formData.get("client_id")?.toString();

      if (!clientId) {
        return { hasAuthMethod: false };
      }

      // 4. Return the extracted credentials.
      // Instead of client_secret, we forward the client certificate payload
      // under the generic response fields required by @saurbit/oauth2.
      return {
        hasAuthMethod: true,
        clientId,
        // Passing the certificate as the secret equivalent so your flow's
        // getClient() callback can validate it against the registered public key/cert.
        clientSecret: clientCertPem,
      };
    } catch {
      return { hasAuthMethod: false };
    }
  }
}
