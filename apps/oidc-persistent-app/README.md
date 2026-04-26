# oidc-persistent-app
An OpenID Connect (OIDC) server implementation built using Bun. This app serves as a playground for exploring OIDC concepts and features, with a focus on persistent key storage.

## PgSQL Schema
The application uses PostgreSQL for persistent storage of cryptographic keys. The schema includes two tables:

### `private_keys`
Stores only one private key along with its metadata, including a wrapped Data Encryption Key (DEK) and an expiration timestamp.

```sql
CREATE TABLE IF NOT EXISTS private_keys
(
    key_id character varying(255) NOT NULL,
    id integer NOT NULL DEFAULT 1,
    private_key text NOT NULL,
    wrapped_dek text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT private_keys_pkey PRIMARY KEY (key_id),
    CONSTRAINT private_keys_id_unique UNIQUE (id),
    CONSTRAINT id CHECK (id = 1)
)
```
### `public_keys`
Stores public keys along with their expiration timestamp.

```sql
CREATE TABLE IF NOT EXISTS public_keys
(
    key_id character varying(255) NOT NULL,
    public_key text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT public_keys_pkey PRIMARY KEY (key_id)
)
```

## Key Management
The application implements a key management strategy that includes:
- **Key Generation**: New key pairs are generated using the `jwksAuthority` module, which creates RSA key pairs for signing JWTs.
- **Key Rotation**: Keys are rotated every 91 days using the `JwksRotator` module, which checks the rotation schedule and generates new keys as needed.
- **Key Storage**: Private keys are encrypted using AES-GCM and stored in the `private_keys` table, while public keys are stored in the `public_keys` table. The encryption and decryption processes ensure that private keys are securely stored and can be retrieved when needed for signing operations.

## Environment Variables
The application requires the following environment variables to be set:
- `DATABASE_URL`: The connection string for the PostgreSQL database.
- `MASTER_KEY`: The master key used for encrypting and decrypting the Data Encryption Key (DEK). It should be a 32-byte key encoded in base64.

## Running the Application
To run the application, follow these steps:
1. Set up the PostgreSQL database and create the necessary tables using the provided SQL schema.
2. Install dependencies using Bun:
   ```bash
   bun install
   ```
3. Set the required environment variables and start the application:
   ```bash
   bunx cross-env DATABASE_URL="your_database_url" MASTER_KEY="your_base64_encoded_master_key" bun dev
   ```
