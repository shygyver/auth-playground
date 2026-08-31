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
 * You must manually inject the cnf claim into the JWT body.
 *
 * ```ts
 * const mtlsTokenType = new MtlsTokenType("x-ssl-client-cert", decodeJwt);
 *
 * const certPem = request.headers.get("x-ssl-client-cert")!;
 * const thumbprint = await mtlsTokenType.calculateX5tS256(certPem);
 *
 * const customClaims = {
 *   cnf: {
 *     "x5t#S256": thumbprint
 *   }
 * };
 * ```
 */
export class MtlsTokenType implements TokenType {
  // RFC 8705 mandates that mTLS-bound access tokens use the "Bearer" prefix
  readonly prefix = "Bearer";

  constructor(
    // Customize based on your reverse proxy configuration
    private readonly certHeaderName: string = "x-ssl-client-cert",
    // Callback to decode/verify your JWT token payload
    private readonly decodeTokenPayload: JwtDecode
  ) {}

  /**
   * Validates the token request at the Token Endpoint before credentials check.
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
   * Validates the token at the Protected Resource Server (API endpoints).
   */
  async isValid(request: Request, token: string): Promise<MtlsTokenTypeValidationResponse> {
    try {
      // 1. Extract the client certificate from the current request
      const currentCertPem = request.headers.get(this.certHeaderName);
      if (!currentCertPem) {
        return {
          isValid: false,
          message: "Client certificate missing on protected resource request.",
        };
      }

      // 2. Decode the JWT payload
      const payload = await this.decodeTokenPayload(token);
      const cnf = payload?.cnf;

      // 3. Confirm the token contains the sender-constrained confirmation claim
      if (!(cnf && typeof cnf === "object" && "x5t#S256" in cnf && cnf["x5t#S256"])) {
        return {
          isValid: false,
          message: "Token validation failed: Missing mTLS token confirmation (cnf) claim.",
        };
      }

      // 4. Compare the WebCrypto-generated thumbprint against the token binding
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
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error: any) {
      return {
        isValid: false,
        message: `mTLS token validation encountered an error: ${error?.message || "Unknown error"}`,
      };
    }
  }

  /**
   * INTERNAL DATABASE HELPER
   * Returns a lowercase Hex string. Use this inside .getClient()
   * to match against standard OpenSSL fingerprints in your DB.
   */
  public async calculateHexThumbprint(pem: string): Promise<string> {
    const hashBuffer = await this.pemToHashBuffer(pem);
    return this.bufferToHex(hashBuffer);
  }

  /**
   * Parses a PEM string, extracts the binary DER bytes, and hashes it
   * using WebCrypto to produce an RFC 8705 compliant base64url SHA-256 thumbprint.
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
