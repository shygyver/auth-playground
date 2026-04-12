import { Pool } from "pg";

const ENV_DATABASE_URL = process.env.DATABASE_URL;

const pool = new Pool({
  connectionString: ENV_DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: {
    rejectUnauthorized: false
  }
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
export async function saveKeyPairRecord(privateKey: PrivateKeyRecord, publicKey: PublicKeyRecord, expirationTime: number) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const createdAt = Date.now();
    const queryPrivateKey = `
            INSERT INTO private_keys (id, key_id, private_key, wrapped_dek, expires_at, created_at) 
            VALUES ($1, $2, $3, $4, to_timestamp($5::bigint / 1000), to_timestamp($6::bigint / 1000))
            ON CONFLICT (id) 
            DO UPDATE SET 
              key_id = EXCLUDED.key_id,
              private_key = EXCLUDED.private_key,
              wrapped_dek = EXCLUDED.wrapped_dek,
              expires_at = EXCLUDED.expires_at,
              created_at = EXCLUDED.created_at
            RETURNING *;
        `;
    const queryPublicKey = `
            INSERT INTO public_keys (key_id, public_key, expires_at, created_at) 
            VALUES ($1, $2, to_timestamp($3::bigint / 1000), to_timestamp($4::bigint / 1000))
        `;
    await client.query(
      queryPrivateKey,
      [1, privateKey.keyId, privateKey.privateKey, privateKey.wrappedDek, expirationTime, createdAt]
    );
    await client.query(
      queryPublicKey,
      [publicKey.keyId, publicKey.publicKey, expirationTime, createdAt]
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
    const res = await pool.query<{ key_id: string; private_key: string; wrapped_dek: string }>(query);

    // Since it's unique, just take the first element.
    if (res.rows.length > 0) {
      const row = res.rows[0];
      return {
        keyId: row.key_id,
        privateKey: row.private_key,
        wrappedDek: row.wrapped_dek
      };
    }
  } catch (err) {
    console.error('Error fetching record:', err);
  }

  return null;
}

export async function getPublicKeyRecords(): Promise<PublicKeyRecord[] | null> {
  const query = 'SELECT * FROM public_keys WHERE expires_at > NOW()';

  try {
    const { rows } = await pool.query<{ key_id: string; public_key: string }>(query);
    return rows.map(row => ({ keyId: row.key_id, publicKey: row.public_key })); // Return all valid public key records
  } catch (err) {
    console.error('Error fetching record:', err);
  }

  return null;
}

export async function getPrivateKeyCreatedAt(): Promise<Date | null> {
  const query = 'SELECT created_at FROM private_keys WHERE expires_at > NOW() LIMIT 1';

  try {
    const { rows } = await pool.query<{ created_at: Date }>(query);

    if (rows.length > 0) {
      return rows[0].created_at;
    }
  } catch (err) {
    console.error('Error fetching record:', err);
  }

  return null;

}