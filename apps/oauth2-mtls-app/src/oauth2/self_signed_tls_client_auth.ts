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

const ALG_MAPPING: Record<string, { name: string; hash?: string; namedCurve?: string }> = {
  // RSA Configurations
  RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  RS384: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
  RS512: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
  PS256: { name: "RSA-PSS", hash: "SHA-256" },
  PS384: { name: "RSA-PSS", hash: "SHA-384" },
  PS512: { name: "RSA-PSS", hash: "SHA-512" },

  // Elliptic Curve Configurations
  ES256: { name: "ECDSA", namedCurve: "P-256" },
  ES384: { name: "ECDSA", namedCurve: "P-384" },
  ES512: { name: "ECDSA", namedCurve: "P-521" },
  // Edwards-curve Digital Signature Algorithm
  EdDSA: { name: "Ed25519" },
};

// Helper to infer the algorithm if the JWK drops the optional 'alg' field
function inferAlgorithmFromJwk(key: { alg?: string; kty: string; crv?: string }): string | null {
  if (key.alg && key.alg in ALG_MAPPING) {
    return key.alg;
  }
  if (key.kty === "RSA") return "RS256"; // Safe default layout for RSA certs
  if (key.kty === "EC") {
    if (key.crv === "P-256") return "ES256";
    if (key.crv === "P-384") return "ES384";
    if (key.crv === "P-521") return "ES512";
  }
  if (key.kty === "OKP") {
    if (key.crv === "Ed25519" || key.crv === "Ed448") {
      return "EdDSA";
    }
  }
  return null;
}

function base64ToArrayBuffer(b64: string): ArrayBuffer {
  const binaryString = atob(b64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Asymmetric signing algorithms supported by the `private_key_jwt` authentication method.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7518#section-3
 */
export enum SelfSignedTlsClientAuthAlgorithms {
  /** RSASSA-PKCS1-v1_5 using SHA-256. */
  RS256 = "RS256",
  /** RSASSA-PKCS1-v1_5 using SHA-384. */
  RS384 = "RS384",
  /** RSASSA-PKCS1-v1_5 using SHA-512. */
  RS512 = "RS512",
  /** RSASSA-PSS using SHA-256. */
  PS256 = "PS256",
  /** RSASSA-PSS using SHA-384. */
  PS384 = "PS384",
  /** RSASSA-PSS using SHA-512. */
  PS512 = "PS512",
  /** ECDSA using P-256 and SHA-256. */
  ES256 = "ES256",
  /** ECDSA using P-384 and SHA-384. */
  ES384 = "ES384",
  /** ECDSA using P-521 and SHA-512. */
  ES512 = "ES512",
  /** Edwards-curve Digital Signature Algorithm (Ed25519 / Ed448). */
  EdDSA = "EdDSA",
}

/**
 * JSON Web Key Set object as defined in RFC 7517.
 * The best practice would be to retrieve this JWKS from a trusted endpoint and cache it for subsequent validations.
 */
export interface TrustedJwks {
  keys: {
    alg?: string;
    kty: string;
    crv?: string;
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
  static algo = SelfSignedTlsClientAuthAlgorithms;

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

  /**
   * The list of accepted asymmetric signing algorithms for self-signed TLS client authentication.
   * Defaults to `[RS256]` if no algorithms have been added via {@link SelfSignedTlsClientAuthMethod.addAlgorithm}.
   */
  get algorithms(): SelfSignedTlsClientAuthAlgorithms[] {
    return this.#algorithms.length ? this.#algorithms : [SelfSignedTlsClientAuthAlgorithms.RS256];
  }

  #algorithms: SelfSignedTlsClientAuthAlgorithms[] = [];

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
   * Adds an asymmetric signing algorithm to the list of accepted algorithms.
   * Duplicate entries are ignored. The list is kept sorted.
   *
   * @param algo - The algorithm to accept.
   */
  addAlgorithm(algo: SelfSignedTlsClientAuthAlgorithms): this {
    if (!this.#algorithms.includes(algo)) {
      this.#algorithms.push(algo);
      this.#algorithms.sort();
    }
    return this;
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
      // Iterate and cryptographically compare the public keys (Standard Web API)
      for (const key of trustedJwks.keys) {
        if (Array.isArray(key.x5c) && key.x5c.length > 0) {
          try {
            // Strip spaces/newlines from the JWKS certificate
            const jwksCleanB64 = key.x5c[0].replace(/[\r\n\s]/g, "");

            // Performance Optimization: If the Base64 strings are a flawless match, pass immediately
            if (clientCertBase64 === jwksCleanB64) {
              isAuthorized = true;
              break;
            }

            // Determine the signature algorithm for this specific key
            const detectedAlg = inferAlgorithmFromJwk(key);

            // Skip if the algorithm is unknown or explicitly not supported by your rules
            if (
              !detectedAlg ||
              !this.#algorithms.includes(detectedAlg as SelfSignedTlsClientAuthAlgorithms)
            ) {
              continue;
            }

            let cryptoConfig = ALG_MAPPING[detectedAlg];
            // Ed448 Edge Case Handling: If it's EdDSA but the JWK explicitly references Ed448
            if (detectedAlg === "EdDSA" && key.crv === "Ed448") {
              cryptoConfig = { name: "Ed448" };
            }

            // Cryptographic Fallback: Import both certificates as SPKI Public Keys using Web Crypto
            // Note: Change to 'ECDSA' / { name: 'ECDSA', namedCurve: 'P-256' } if using Elliptic Curve certs
            const clientKey = await crypto.subtle.importKey(
              "spki",
              base64ToArrayBuffer(clientCertBase64),
              cryptoConfig,
              true,
              ["verify"]
            );

            const jwksKey = await crypto.subtle.importKey(
              "spki",
              base64ToArrayBuffer(jwksCleanB64),
              cryptoConfig,
              true,
              ["verify"]
            );

            // Export keys to raw SPKI structural bytes to abstract away encoding differences
            const clientRaw = await crypto.subtle.exportKey("spki", clientKey);
            const jwksRaw = await crypto.subtle.exportKey("spki", jwksKey);

            const clientArr = new Uint8Array(clientRaw);
            const jwksArr = new Uint8Array(jwksRaw);

            // Secure, timing-safe evaluation of the public key byte arrays
            if (
              clientArr.length === jwksArr.length &&
              clientArr.every((val, i) => val === jwksArr[i])
            ) {
              isAuthorized = true;
              break;
            }
          } catch (err) {
            // Skip malformed entries in the JWKS loop gracefully
            continue;
          }
        }
      }
      /*
      // Scan the JWKS for a matching cryptographic key (jose)
      for (const key of trustedJwks.keys) {
        if (Array.isArray(key.x5c) && key.x5c.length > 0) {
          try {
            // Enforce your algorithm whitelist rules early
            // (jose allows you to read or infer algorithm properties cleanly)
            const algToCheck = key.alg || (key.kty === 'RSA' ? 'RS256' : key.kty === 'EC' ? 'ES256' : 'EdDSA');
            if (!this.#algorithms.includes(algToCheck as SelfSignedTlsClientAuthAlgorithms)) continue;

            // 3. Let 'jose' dynamically import the JWK entry into a runtime KeyObject
            const jwksKeyObject = await jose.importJWK(key, algToCheck);

            // 4. Let 'jose' dynamically import the incoming raw client certificate string
            const clientKeyObject = await jose.importX509(rawIncomingPem, algToCheck);

            // 5. Direct cryptographic object comparison
            // jose normalizes the underlying keys, allowing a safe, standard check
            if (JSON.stringify(await jose.exportJWK(clientKeyObject)) === JSON.stringify(await jose.exportJWK(jwksKeyObject))) {
              isAuthorized = true;
              break;
            }
          } catch (err) {
            // Fall through to the next key if a structural decoding error occurs
            continue;
          }
        }
      }
      */

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
