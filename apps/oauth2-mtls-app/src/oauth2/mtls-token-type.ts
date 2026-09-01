import { MtlsClientAuthMethod } from "./mtls-client-auth-method";
import type {
  JwtDecode,
  JwtPayload,
  TokenType,
  TokenTypeValidationResponse,
} from "@saurbit/oauth2";

export interface MtlsTokenTypeValidationResponse extends TokenTypeValidationResponse {
  data?: {
    mtlsPayload: JwtPayload;
    mtlsThumbprint?: string;
  };
}

/**
 * {@link TokenType} implementation for the mTLS (Mutual TLS) token scheme.
 *
 * Validates mTLS-bound access tokens on both the token endpoint and protected resource endpoints,
 * ensuring that the presenting client certificate matches the token binding.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8705
 */
export class MtlsTokenType implements TokenType {
  // RFC 8705 mandates that mTLS-bound access tokens use the "Bearer" prefix
  readonly prefix = "Bearer";

  /**
   * Creates a new `MtlsTokenType` instance.
   *
   * @param decodeTokenPayload - Callback to decode/verify your JWT token payload.
   * @param certHeaderName - The HTTP header name where the client certificate is expected (default: "x-ssl-client-cert").
   */
  constructor(
    // Callback to decode/verify your JWT token payload
    private readonly decodeTokenPayload: JwtDecode,
    // Customize based on your reverse proxy configuration
    private readonly certHeaderName: string = "x-ssl-client-cert"
  ) {}

  /**
   * Validates the mTLS client certificate on an incoming token endpoint request.
   * Called before client credentials are verified.
   *
   * @param req - The incoming token endpoint HTTP request.
   * @returns A validation response indicating whether the mTLS client certificate is present.
   */
  async isValidTokenRequest(request: Request): Promise<TokenTypeValidationResponse> {
    const clientCertPem = request.headers.get(this.certHeaderName);

    if (!clientCertPem) {
      return {
        isValid: false,
        message: "Mutual TLS client certificate missing from token request header.",
      };
    }

    return { isValid: true };
  }

  /**
   * Validates the mTLS client certificate on an incoming protected resource request.
   *
   * @param request - The incoming HTTP request.
   * @param token - The mTLS-bound access token extracted from the `Authorization` header.
   * @returns A validation response indicating whether the proof and token are valid.
   */
  async isValid(request: Request, token: string): Promise<MtlsTokenTypeValidationResponse> {
    try {
      // Extract the client certificate from the current request
      const currentCertPem = request.headers.get(this.certHeaderName);
      if (!currentCertPem) {
        return {
          isValid: false,
          message: "Client certificate missing on protected resource request.",
        };
      }

      // Decode the JWT payload
      const payload = await this.decodeTokenPayload(token);
      const cnf = payload?.cnf;

      // Confirm the token contains the sender-constrained confirmation claim
      if (!(cnf && typeof cnf === "object" && "x5t#S256" in cnf && cnf["x5t#S256"])) {
        return {
          isValid: false,
          message: "Token validation failed: Missing mTLS token confirmation (cnf) claim.",
        };
      }

      // Compare the WebCrypto-generated thumbprint against the token binding
      const currentThumbprint = await this.calculateX5tS256(currentCertPem);
      if (currentThumbprint !== cnf["x5t#S256"]) {
        return {
          isValid: false,
          message: "Token sender mismatch: Presenting certificate does not match token binding.",
        };
      }

      return {
        isValid: true,
        data: {
          mtlsPayload: payload,
          mtlsThumbprint: currentThumbprint,
        },
      };
    } catch (error) {
      return {
        isValid: false,
        message: `mTLS token validation encountered an error: ${error instanceof Error ? error.message : "Unknown error"}`,
      };
    }
  }

  /**
   * Update the claims of a JWT payload to include the mTLS certificate thumbprint in the `cnf` claim.
   * Use this when issuing an mTLS-bound access token to bind it to the public key of the client certificate.
   *
   * @param claims - The JWT claims object to which the mTLS certificate thumbprint will be added.
   * @param thumbprint - The mTLS certificate thumbprint to add to the `cnf` claim.
   * @returns The updated JWT claims object.
   * @throws If the claims object is invalid or the thumbprint is not a non-empty string.
   */
  addThumbprintToCnfClaim(claims: JwtPayload, thumbprint: string): JwtPayload {
    if (!claims || typeof claims !== "object") {
      throw new Error("Invalid claims object");
    }
    let tmpThumbprint: string | undefined;
    if (typeof thumbprint === "string" && thumbprint.length > 0) {
      tmpThumbprint = thumbprint;
    } else {
      throw new Error("Invalid thumbprint argument");
    }
    const cnf: Record<string, unknown> =
      claims.cnf && typeof claims.cnf === "object" ? (claims.cnf as Record<string, unknown>) : {};
    cnf["x5t#S256"] = tmpThumbprint;
    claims.cnf = cnf;
    return claims;
  }

  /**
   * Creates a new instance of the mTLS client authentication method using the configured certificate header name.
   * @returns An instance of the mTLS client authentication method.
   */
  createClientAuthMethod(): MtlsClientAuthMethod {
    return new MtlsClientAuthMethod(this.certHeaderName);
  }

  /**
   * Calculates the lowercase hexadecimal SHA-256 thumbprint of a PEM-encoded client certificate.
   * This method could be useful for other verification purposes.
   *
   * Not officially part of the mTLS binding process.
   *
   * @param pem - The PEM-encoded client certificate.
   * @returns The lowercase hexadecimal SHA-256 thumbprint of the certificate.
   */
  public async calculateHexThumbprint(pem: string): Promise<string> {
    const hashBuffer = await this.pemToHashBuffer(pem);
    return this.bufferToHex(hashBuffer);
  }

  /**
   * Parses a PEM string, extracts the binary DER bytes, and hashes it
   * using WebCrypto to produce an RFC 8705 compliant base64url SHA-256 thumbprint.
   *
   * @param pem - The PEM-encoded client certificate.
   * @returns The base64url-encoded SHA-256 thumbprint of the certificate.
   */
  public async calculateX5tS256(pem: string): Promise<string> {
    const hashBuffer = await this.pemToHashBuffer(pem);
    // Convert the resulting ArrayBuffer to a base64url encoded string without padding
    return this.bufferToBase64Url(hashBuffer);
  }

  /** Common WebCrypto core processor */
  private async pemToHashBuffer(pem: string): Promise<ArrayBuffer> {
    // Clean URL-encoded format if it exists, headers, footers, and whitespace to extract the raw base64 data
    const decodedPem = pem.includes("%") ? decodeURIComponent(pem) : pem;
    const cleanBase64 = decodedPem
      .replace(/-----BEGIN CERTIFICATE-----/, "")
      .replace(/-----END CERTIFICATE-----/, "")
      .replace(/\s+/g, "");

    // Convert base64 back into an ArrayBuffer containing raw DER binary data
    const binaryString = atob(cleanBase64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    // Digest via the WebCrypto API
    return await crypto.subtle.digest("SHA-256", bytes.buffer);
  }

  /**
   * Converts an ArrayBuffer directly to a lowercase hexadecimal string.
   * This perfectly matches standard OpenSSL sha256 fingerprints.
   */
  private bufferToHex(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let hex = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      // Convert byte to hex and pad with a leading zero if necessary
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex.toLowerCase();
  }

  /**
   * Helper to convert an ArrayBuffer directly to base64url (RFC 4648)
   */
  private bufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); // Strip any trailing padding characters
  }
}
