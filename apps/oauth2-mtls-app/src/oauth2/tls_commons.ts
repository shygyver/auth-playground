export interface TlsClientAuthHeadersValues {
  cert: string;
  certVerify: string;
  certDn?: string;
  certSan?: string;
  certExpire?: string;
  additionalHeaders?: Record<string, string>;
}
