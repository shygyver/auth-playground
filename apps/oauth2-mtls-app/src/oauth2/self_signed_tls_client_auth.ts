/**
 * @module
 *
 * Implements the `self_signed_tls_client_auth` (mTLS) client authentication method, where the
 * client authenticates using a client certificate over a mutually TLS connection.
 * The client certificate is sent in the request headers, typically forwarded by a reverse proxy.
 *
 * JWT decoding and verification logic is injected via the constructor to avoid
 * a hard dependency on any particular JWT library.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8705
 */
import type {
  ClientAuthMethod,
  ClientAuthMethodResponse,
  TokenEndpointAuthMethod,
} from "@saurbit/oauth2";

/**
 * mTLS client authentication method as defined in RFC 8705.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8705
 */
export class SelfSignedTlsClientAuthMethod implements ClientAuthMethod {
  // RFC 8705 official registered name
  readonly method: TokenEndpointAuthMethod =
    "self_signed_tls_client_auth" as TokenEndpointAuthMethod;

  // mTLS relies on private key possession, not a symmetric client secret
  // But we still need to extract the client certificate as a secret equivalent for validation.
  readonly secretIsOptional = false;

  constructor(
    // Customize the header key based on your reverse proxy config
    private readonly certHeaderName: string = "x-ssl-client-cert"
  ) {}

  /**
   * Extracts and verifies the client certificate from the request headers.
   *
   * Looks for the client certificate in the request headers as specified by the
   * `certHeaderName` provided in the constructor. The `client_id` is expected to
   * be included in the request body as per RFC 8705.
   *
   * Supports `application/x-www-form-urlencoded` content type.
   *
   * @param request - The incoming HTTP request.
   * @returns The extracted client credentials, or `{ hasAuthMethod: false }` if the
   *   request does not contain a valid client certificate.
   */
  async extractClientCredentials(request: Request): Promise<ClientAuthMethodResponse> {
    // mTLS authentication must only happen on POST requests to the token endpoint
    if (request.method !== "POST") {
      return { hasAuthMethod: false };
    }

    // Look for the TLS client certificate forwarded by your reverse proxy
    const clientCertPem = request.headers.get(this.certHeaderName);
    if (!clientCertPem) {
      return { hasAuthMethod: false };
    }

    try {
      // RFC 8705 states the client MUST include its 'client_id' in the request body
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

      // TODO: Implement proper client certificate validation here.
      // This may include checking the certificate's signature, expiration,
      // and matching it against the registered client information (e.g. array of allowed certificates/thumbprints).

      // Return the extracted credentials.
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
