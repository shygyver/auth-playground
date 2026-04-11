import { Pool } from "pg";

const ENV_DB_HOST = process.env.DB_HOST || "localhost";
const ENV_DB_PORT = parseInt(process.env.DB_PORT || "5432");
const ENV_DB_USER = process.env.DB_USER || "postgres";
const ENV_DB_PASSWORD = process.env.DB_PASSWORD || "password";
const ENV_DB_NAME = process.env.DB_NAME || "oidc_persistent_app"; 

const pool = new Pool({
  host: ENV_DB_HOST,
  port: ENV_DB_PORT,
  user: ENV_DB_USER,
  password: ENV_DB_PASSWORD,
  database: ENV_DB_NAME
});

export interface PrivateKeyRecord {
  keyId: string;
  privateKey: string;
  wrappedDek: string;
}

export interface PublicKeyRecord {
  keyId: string;
  publicKey: string;
}

/**
 * Saves the encrypted private key and public key to the database with an expiration time.
 * @param privateKey The encrypted private key record.
 * @param publicKey The public key record.
 * @param expirationTime The expiration time in milliseconds since the Unix epoch.
 */
export async function saveKeyPair(privateKey: PrivateKeyRecord, publicKey: PublicKeyRecord, expirationTime: number) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const queryPrivateKey = `
            INSERT INTO private_keys (id, key_id, private_key, wrapped_dek, expires_at) 
            VALUES ($1, $2, $3, $4, to_timestamp($5 / 1000))
            ON CONFLICT (id) 
            DO UPDATE SET 
              key_id = EXCLUDED.key_id,
              private_key = EXCLUDED.private_key,
              wrapped_dek = EXCLUDED.wrapped_dek,
              expires_at = EXCLUDED.expires_at
            RETURNING *;
        `;
    const queryPublicKey = `
            INSERT INTO public_keys (key_id, public_key, expires_at) 
            VALUES ($1, $2, to_timestamp($3 / 1000))
        `;
    await client.query(
      queryPrivateKey,
      [1, privateKey.keyId, privateKey.privateKey, privateKey.wrappedDek, expirationTime]
    );
    await client.query(
      queryPublicKey,
      [publicKey.keyId, publicKey.publicKey, expirationTime]
    );
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

export async function getPrivateKeyRecord(): Promise<PrivateKeyRecord | null> {
  const query = 'SELECT * FROM private_keys WHERE expires_at > NOW() LIMIT 1';

  try {
    const res = await pool.query(query);

    // Since it's unique, just take the first element.
    if (res.rows.length > 0) {
      return res.rows[0];
    }
  } catch (err) {
    console.error('Error fetching record:', err);
  }

  return null;
}

export async function getPublicKeyRecords(): Promise<PublicKeyRecord[] | null> {
  const query = 'SELECT * FROM public_keys WHERE expires_at > NOW()';

  try {
    const { rows } = await pool.query(query);
    return rows; // Return all valid public key records
  } catch (err) {
    console.error('Error fetching record:', err);
  }

  return null;
}