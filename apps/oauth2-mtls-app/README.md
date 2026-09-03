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