/**
 * @module
 *
 * Implements the `tls_client_auth` (mTLS) client authentication method, where the
 * client authenticates using a client certificate over a mutually TLS connection.
 * The client certificate is sent in the request headers, typically forwarded by a reverse proxy.
 *
 * JWT decoding and verification logic is injected via the constructor to avoid
 * a hard dependency on any particular JWT library.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8705
 */
import { MtlsCertificateBoundTokenType } from "./mtls_certificate_bound_token_type";
import { TlsClientAuthHeadersValues } from "./tls_commons";
import type {
  ClientAuthMethod,
  ClientAuthMethodResponse,
  JwtDecode,
  TokenEndpointAuthMethod,
} from "@saurbit/oauth2";

export interface TlsClientAuthHandler {
  (clientId: string, headers: TlsClientAuthHeadersValues): boolean | Promise<boolean>;
}

export interface TlsClientAuthOptions {
  certHeaderName?: string;
  certVerifyHeaderName?: string;
  certDnHeaderName?: string;
  certSanHeaderName?: string;
  certExpireHeaderName?: string;
  additionalHeadersNames?: string[];
  validateClientSubject?: TlsClientAuthHandler;
}

/**
 * TLS client authentication method as defined in RFC 8705.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8705
 *
 * This class provides a way to extract and validate client certificates from HTTP requests.
 * It allows you to configure the headers used to forward the client certificate and its verification status.
 * It also provides a mechanism to validate the client certificate against the client ID.
 * This class is useful in scenarios where client authentication needs to be performed using TLS client certificates, such as in secure API communications.
 * @example
 * const tlsAuth = new TlsClientAuthMethod({
 *   certHeaderName: "x-ssl-client-cert",
 *   certVerifyHeaderName: "x-ssl-client-verify",
 *   certDnHeaderName: "x-ssl-client-dn",
 *   certSanHeaderName: "x-ssl-client-san",
 *   certExpireHeaderName: "x-ssl-client-expire",
 * });
 *
 * tlsAuth.validateClientSubject(async (clientId, headers) => {
 *   // Implement your certificate validation logic here
 *   return true;
 * });
 *
 */
export class TlsClientAuthMethod implements ClientAuthMethod {
  // RFC 8705 official registered name
  readonly method: TokenEndpointAuthMethod = "tls_client_auth" as TokenEndpointAuthMethod;

  // mTLS relies on private key possession, not a symmetric client secret
  // But we still need to extract the client certificate as a secret equivalent for validation.
  readonly secretIsOptional = false;

  #certHeaderName: string;
  #certVerifyHeaderName: string;
  #certDnHeaderName: string;
  #certSanHeaderName: string;
  #certExpireHeaderName: string;
  #additionalHeadersNames: string[];

  #handler: (clientId: string, headers: TlsClientAuthHeadersValues) => boolean | Promise<boolean>;

  /**
   * Initializes a new instance of the TLS client authentication method.
   *
   * @param headers - The headers configuration for the TLS client authentication method.
   * Defaults will be used if not provided.
   */
  constructor(
    // Customize the header key based on your reverse proxy config
    options: TlsClientAuthOptions = {}
  ) {
    this.#certHeaderName = options.certHeaderName ?? "x-ssl-client-cert";
    this.#certVerifyHeaderName = options.certVerifyHeaderName ?? "x-ssl-client-verify";
    this.#certDnHeaderName = options.certDnHeaderName ?? "x-ssl-client-dn";
    this.#certSanHeaderName = options.certSanHeaderName ?? "x-ssl-client-san";
    this.#certExpireHeaderName = options.certExpireHeaderName ?? "x-ssl-client-expire";
    this.#additionalHeadersNames = options.additionalHeadersNames ?? [];

    this.#handler = options.validateClientSubject ?? (() => Promise.resolve(false));
  }

  /**
   * Sets the handler function used to validate the client certificate.
   *
   * Validate the Subject Distinguished Name (DN) or Subject Alternative Name (SAN)
   * and other relevant information extracted from the client certificate.
   *
   * @param handler - A function that validates the client certificate for the given client ID.
   * @returns The current instance for method chaining.
   */
  validateClientSubject(
    handler: (clientId: string, headers: TlsClientAuthHeadersValues) => boolean | Promise<boolean>
  ): this {
    this.#handler = handler;
    return this;
  }

  createCertificateBoundTokenType(decodeTokenPayload: JwtDecode) {
    return new MtlsCertificateBoundTokenType(decodeTokenPayload, this.#certHeaderName);
  }

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
    const clientCertPem = request.headers.get(this.#certHeaderName);
    const clientCertVerify = request.headers.get(this.#certVerifyHeaderName);
    const clientCertDn = request.headers.get(this.#certDnHeaderName);
    const clientCertSan = request.headers.get(this.#certSanHeaderName);
    const clientCertExpire = request.headers.get(this.#certExpireHeaderName);
    const additionalHeaders: Record<string, string> = {};
    if (!clientCertPem || clientCertVerify !== "SUCCESS") {
      return { hasAuthMethod: false };
    }
    for (const headerName of this.#additionalHeadersNames) {
      const headerValue = request.headers.get(headerName);
      if (headerValue) {
        additionalHeaders[headerName] = headerValue;
      }
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

      // Implement proper client certificate validation here.
      // This may include checking the certificate's signature, expiration,
      // and matching it against the registered client information (e.g. array of allowed certificates/thumbprints).
      const isValidClient = await this.#handler(clientId, {
        cert: clientCertPem,
        certVerify: clientCertVerify,
        certDn: clientCertDn ?? undefined,
        certSan: clientCertSan ?? undefined,
        certExpire: clientCertExpire ?? undefined,
        additionalHeaders,
      });
      if (!isValidClient) {
        return { hasAuthMethod: false };
      }

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
