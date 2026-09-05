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
import { TlsClientAuthHeadersValues } from "./tls_commons";
import type {
  ClientAuthMethod,
  ClientAuthMethodResponse,
  TokenEndpointAuthMethod,
} from "@saurbit/oauth2";

/**
 * JSON Web Key Set object as defined in RFC 7517.
 * The best practice would be to retrieve this JWKS from a trusted endpoint and cache it for subsequent validations.
 */
export interface TrustedJwks {
  keys: {
    alg?: string;
    /**
     * The X.509 certificate chain for the key, represented as an array of base64-encoded DER certificates.
     * The framework parses that x5c string, converts it back into a public key object or certificate,
     * and matches it against the incoming TLS certificate.
     */
    x5c?: string[];
    [propName: string]: unknown;
  }[];
}

export interface TrustedJwksHandler {
  (clientId: string, headers: TlsClientAuthHeadersValues): TrustedJwks | Promise<TrustedJwks>;
}

export interface SelfSignedTlsClientAuthOptions {
  certHeaderName?: string;
  certVerifyHeaderName?: string;
  certDnHeaderName?: string;
  certSanHeaderName?: string;
  certExpireHeaderName?: string;
  additionalHeadersNames?: string[];
  getJwks?: TrustedJwksHandler;
}

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

  #certHeaderName: string;
  #certVerifyHeaderName: string;
  #certDnHeaderName: string;
  #certSanHeaderName: string;
  #certExpireHeaderName: string;
  #additionalHeadersNames: string[];

  #getJwks?: TrustedJwksHandler;

  constructor(options: SelfSignedTlsClientAuthOptions = {}) {
    this.#certHeaderName = options.certHeaderName ?? "x-ssl-client-cert";
    this.#certVerifyHeaderName = options.certVerifyHeaderName ?? "x-ssl-client-verify";
    this.#certDnHeaderName = options.certDnHeaderName ?? "x-ssl-client-dn";
    this.#certSanHeaderName = options.certSanHeaderName ?? "x-ssl-client-san";
    this.#certExpireHeaderName = options.certExpireHeaderName ?? "x-ssl-client-expire";
    this.#additionalHeadersNames = options.additionalHeadersNames ?? [];
    this.#getJwks = options.getJwks;
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
    if (!clientCertPem || clientCertVerify == "NONE" || clientCertVerify == null) {
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

      const rawIncomingPem = decodeURIComponent(clientCertPem);
      const clientCertBase64 = rawIncomingPem
        .replace(/-----\s*BEGIN ?[^-]*-----\s*/g, "")
        .replace(/-----\s*END ?[^-]*-----\s*/g, "")
        .replace(/[\r\n\s]/g, ""); // Removes all newlines and spaces

      // Fetch JWKS from trusted URI.
      const trustedJwks = await this.#getJwks?.(clientId, {
        cert: clientCertPem,
        certVerify: clientCertVerify,
        certDn: clientCertDn ?? undefined,
        certSan: clientCertSan ?? undefined,
        certExpire: clientCertExpire ?? undefined,
        additionalHeaders,
      });

      if (!trustedJwks) {
        return { hasAuthMethod: false };
      }

      // Scan the JWKS for a matching certificate string.
      let isAuthorized = false;
      for (const key of trustedJwks.keys) {
        if (key.x5c && key.x5c.length > 0) {
          const jwksCertBase64 = key.x5c[0].replace(/[\r\n\s]/g, ""); // Ensure no white spaces

          if (clientCertBase64 === jwksCertBase64) {
            isAuthorized = true;
            break;
          }
        }
      }

      if (!isAuthorized) {
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
