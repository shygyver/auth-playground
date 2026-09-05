# mTLS Setup Instructions

Use in Linux or WSL.

## Prerequisites

- OpenSSL installed
- curl installed

## Steps

### Creating Certificates

```bash
mkdir certs && cd certs

# 1. Create a private local Certificate Authority (CA)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=Local-Testing-CA"

# 2. Create the Nginx Server Certificate Layout
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# 3. Create the Client Certificate Layout 
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=test-developer-client/O=DevTeam"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
```

Get the thumbprint of the client certificate for registration purposes. You can use the following command:

```bash
openssl x509 -in client.crt -outform DER | openssl dgst -sha256 -binary | openssl base64 | tr -d '=' | tr '/+' '_-'
```

Save the output as the thumbprint of the client certificate for registration purposes.

### Nginx Configuration

Replace server_name and proxy_pass with your actual domain and backend service URL.

```conf
events { 
    worker_connections 1024; 
}

http {
    server {
        listen 443 ssl;
        server_name localhost;

        # Server credentials (so client trusts Nginx)
        ssl_certificate     /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;

        # Mutual TLS Configuration
        ssl_client_certificate /etc/nginx/certs/ca.crt; # The CA that signed client certs
        ssl_verify_client      on;                       # Rejects requests without valid client certs

        location / {
            proxy_pass http://oauth2-mtls-app:3000;

            # If a cert was provided, check NGINX's built-in validation (e.g., expiration)
            # NGINX automatically sets $ssl_client_verify to 'SUCCESS', 'FAILED:reason', or 'NONE'
            if ($ssl_client_verify ~ "^FAILED:certificate\s+has\s+expired$") {
                return 401 "{\"error\": \"invalid_client\", \"error_description\": \"Client certificate expired\"}";
            }
            
            # Forward connection context
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Pass mTLS data to the backend service
            proxy_set_header X-SSL-Client-Verify $ssl_client_verify; # Returns "SUCCESS", "FAILED", or "NONE"
            proxy_set_header X-SSL-Client-DN     $ssl_client_s_dn;   # Subject Distinguished Name
            proxy_set_header X-SSL-Client-Cert   $ssl_client_escaped_cert; # Safe URL-encoded certificate string
            proxy_set_header X-SSL-Client-SAN    ""; # Subject Alternative Name(s) from the client certificate
            proxy_set_header X-SSL-Client-Expire $ssl_client_v_end; # Certificate expiration date
        }
    }
}
```

### Testing the Setup

```bash
curl -v --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key https://localhost/
```

### Token request

```bash
curl -X POST https://localhost/token \
  --cacert certs/ca.crt \
  --cert certs/client.crt \
  --key certs/client.key \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=example-client" \
  -v
```

Or limit the access to specific scopes:

```bash
curl -X POST https://localhost/token \
  --cacert certs/ca.crt \
  --cert certs/client.crt \
  --key certs/client.key \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=example-client" \
  -d "scope=content:read content:write" \
  -v
```


### Accessing a Protected Resource

```bash
curl -X GET https://localhost/api/protected-resource \
  --cacert certs/ca.crt \
  --cert certs/client.crt \
  --key certs/client.key \
  -H "Authorization: Bearer YOUR_COPIED_TOKEN_STRING" \
  -v
```

## Docker Compose example

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - oauth2-mtls-app

  oauth2-mtls-app:
    build: ./oauth2-mtls-app
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
```

## Self-signed Certificates

To generate self-signed certificates for testing purposes, you can use the following commands:
```bash
# 1. Create the Client Private Key
openssl genrsa -out client.key 2048

# 2. Create and Sign the Self-Signed Client Certificate in one step
openssl req -new -x509 -days 365 \
  -key client.key \
  -out client.crt \
  -subj "/CN=test-client-id"
```

The client should use the generated `client.crt` during the TLS handshake and also extract the public key from client.crt, formats it as a JWK, and publishes it to its JWKS endpoint.

Here is a quick NodeJS script to convert the client certificate to a JWK:

```js
import * as fs from 'node:fs';
import * as jose from 'jose';

async function convertCertToJwk(certPath, algorithm = 'RS256') {
  try {
    // 1. Read the raw client certificate PEM file
    const rawPem = fs.readFileSync(certPath, 'utf8');

    // 2. Clean the PEM string to create the raw base64 string for the x5c array
    const cleanB64 = rawPem
      .replace(/-----\s*BEGIN ?[^-]*-----\s*/g, "")
      .replace(/-----\s*END ?[^-]*-----\s*/g, "")
      .replace(/[\r\n\s]/g, "");

    // 3. Import the certificate as a native CryptoKey object
    const publicKey = await jose.importX509(rawPem, algorithm);

    // 4. Export the CryptoKey object into standard JWK properties
    const jwk = await jose.exportJWK(publicKey);

    // 5. Structure the final JWK matching RFC 7517 / RFC 8705 specifications
    const completeJwk = {
      kty: jwk.kty,
      alg: algorithm,
      use: 'sig',
      n: jwk.n, // Present if RSA
      e: jwk.e, // Present if RSA
      x: jwk.x, // Present if EC / OKP
      y: jwk.y, // Present if EC
      crv: jwk.crv, // Present if EC / OKP
      x5c: [cleanB64] // The critical certificate array for mTLS validation
    };

    console.log(JSON.stringify(completeJwk, null, 2));
  } catch (error) {
    console.error('Failed to convert certificate:', error.message);
  }
}

// Execute the conversion (Change path and algorithm as needed)
convertCertToJwk('./client.crt', 'RS256');
```

In your NGINX config, you set:

```conf
ssl_verify_client optional_no_ca;
```

This tells NGINX to **not** validate the certificates against a CA.