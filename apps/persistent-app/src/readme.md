To store and rotate keys in PostgreSQL using Node.js, you can use a combination of a JSONB array for public key history and an UPSERT (using ON CONFLICT) to overwrite the private key. Since PostgreSQL does not have a native "Time-to-Live" (TTL) feature like Redis, you can implement one using a background cleanup function or a database trigger. [1, 2, 3, 4, 5] 
## 1. Database Schema
Use the JSONB type for public keys to store an array of previous keys, and a timestamp to track expiration.

```sql
CREATE TABLE key_store (
    key_id VARCHAR(255) PRIMARY KEY,
    private_key TEXT NOT NULL,
    public_keys JSONB DEFAULT '[]'::jsonb, -- Stores history of public keys
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    wrapped_dek TEXT NOT NULL -- For storing the wrapped Data Encryption Key (DEK)
);
```

## 2. Implementation in Node.js
You can use the [node-postgres (pg)](https://node-postgres.com/) library to handle the rotation logic. The following query performs the "rotation" by overwriting the private key and appending the new public key to the existing array. [6, 7] 

```js
const { Pool } = require('pg');
const pool = new Pool();

async function rotateKeys(id, newPrivate, newPublic, ttlHours = 24) {
    const expiration = new Date();
    expiration.setHours(expiration.getHours() + ttlHours);

    const query = `
        INSERT INTO key_store (key_id, private_key, public_keys, expires_at, wrapped_dek)
        VALUES ($1, $2, jsonb_build_array($3), $4, $5)
        ON CONFLICT (key_id) DO UPDATE SET
            private_key = EXCLUDED.private_key,
            public_keys = key_store.public_keys || jsonb_build_array($3::text),
            expires_at = EXCLUDED.expires_at,
            wrapped_dek = EXCLUDED.wrapped_dek;
    `;

    try {
        await pool.query(query, [id, newPrivate, newPublic, expiration]);
        console.log('Keys rotated successfully');
    } catch (err) {
        console.error('Rotation failed:', err);
    }
}
```

## 3. Handling TTL (Automatic Deletion)
Because PostgreSQL is transactional and ACID-compliant, it doesn't automatically delete rows when they expire. You have two main options: [1] 

* Background Worker (Recommended): Set up a setInterval in your Node.js app to periodically delete expired keys.

```js
setInterval(async () => {
    await pool.query('DELETE FROM key_store WHERE expires_at < NOW()');
}, 60000); // Check every minute
```

* Database Trigger: You can create a trigger that deletes expired rows whenever a new INSERT occurs, though this can slightly impact write performance.
* Postgres Extensions: For high-volume environments, consider extensions like [pg_ttl_index](https://pgxn.org/dist/pg_ttl_index/) which automate cleanup using background workers. [2, 3] 

## Security Recommendations

* Encryption: Do not store private keys in plain text. Use a symmetric encryption algorithm (like AES-256-GCM) with a master key stored in an environment variable or a secret manager.
* Type Choice: Use TEXT or BYTEA for key storage instead of VARCHAR to handle variable key lengths without unnecessary indexing overhead.


---

# Key Management Best Practices: "Master Key" vs "Key Wrap" Approaches

When it comes to securely managing encryption keys, there are two primary approaches: the "Master Key" approach and the "Key Wrap" approach.

The "Key Wrap" approach (often called Envelope Encryption) is the standard industry practice for professional systems. [1, 2] 
Major providers like AWS (KMS), Google Cloud, and Azure all use this exact method. It follows the principle of a Key Hierarchy, which is a core recommendation in NIST SP 800-57 guidelines. [2, 3, 4, 5, 6] 
## Why the "Key Wrap" approach is the standard:

   1. Limited Exposure: The "Master Key" (Key Encryption Key or KEK) stays locked in your most secure environment (like a hardware module or a secret manager) and is only used to encrypt small data keys.
   2. Scalability: You can have thousands of unique "Data Keys" (DEKs) for different users or files. If one DEK is compromised, only that specific data is at risk, not your entire system.
   3. Easier Rotation: You can rotate the Master Key without having to re-encrypt every single piece of data in your database. You only need to re-encrypt the small "wrapped" keys. [1, 2, 7, 8, 9] 

## How the Standard Workflow Looks:

* Generation: You generate a unique DEK (the raw key) for every new private key.
* Encryption: You use the DEK to encrypt your private key.
* Wrapping: You use the KEK (from your .env) to encrypt the DEK.
* Storage: You store the Encrypted Private Key and the Wrapped DEK together in your database. [2, 4, 5, 10, 11] 

## When to use each:

* Master Approach: Only suitable for local tutorials or very small, non-critical projects. It’s easier to code but doesn't teach real-world production habits.
* Key Wrap Approach: Use this for any professional application. It teaches the "Gold Standard" architecture used in financial and cloud-native security. [2, 7, 10] 

Would you like to see how to implement the standard key wrapping logic in your code?

[1] [https://docs.aws.amazon.com](https://docs.aws.amazon.com/kms/latest/developerguide/kms-cryptography.html)
[2] [https://dev.ubiqsecurity.com](https://dev.ubiqsecurity.com/docs/key-mgmt-best-practices)
[3] [https://terrazone.io](https://terrazone.io/nist-800-57/)
[4] [https://www.youtube.com](https://www.youtube.com/watch?v=OPCzAwY3Wj4)
[5] [https://www.cloudthat.com](https://www.cloudthat.com/resources/blog/envelope-encryption-using-aws-kms)
[6] [https://en.wikipedia.org](https://en.wikipedia.org/wiki/Key_management)
[7] [https://www.kiteworks.com](https://www.kiteworks.com/regulatory-compliance/encryption-key-rotation-strategies/)
[8] [https://cpl.thalesgroup.com](https://cpl.thalesgroup.com/blog/data-protection/encryption-key-rotation-data-security)
[9] [https://dev.ubiqsecurity.com](https://dev.ubiqsecurity.com/docs/key-mgmt-best-practices)
[10] [https://docs.aws.amazon.com](https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html)
[11] [https://www.cyberark.com](https://www.cyberark.com/resources/blog/the-importance-of-key-management-in-cryptography)

---

# Implementing Envelope Encryption (Key Wrapping) for Secure Key Storage

The industry standard is Envelope Encryption (Key Wrapping). In this model, you generate a unique Data Encryption Key (DEK) for every record, use it to encrypt your private key, and then "wrap" (encrypt) that DEK with your Master Key (KEK). [1, 2, 3, 4, 5] 
## Key Rotation Workflow
For each rotation:

   1. Generate a new DEK: A unique 32-byte key for the current rotation.
   2. Encrypt the Private Key: Use the new DEK and AES-256-GCM.
   3. Wrap the DEK: Use your Master Key (KEK) from your environment variables to encrypt the DEK itself.
   4. Store everything: Save the encrypted private key and the wrapped DEK in your database. [3, 6, 7, 8] 

## Universal implementation (Web Crypto)

```js
// HELPER: Encrypt data using a provided key (Standard AES-GCM)
async function encryptWithKey(plaintext, rawKey) {
    const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
    
    // Combine IV + ciphertext for storage
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return combined;
}
// MAIN: Wrap and store logic
async function rotateAndWrap(privateKeyToStore, masterKeyRaw) {
    // 1. Generate a fresh, unique DEK (Data Encryption Key)
    const dekRaw = crypto.getRandomValues(new Uint8Array(32));

    // 2. Encrypt the Private Key with the DEK
    const encryptedPrivateKey = await encryptWithKey(privateKeyToStore, dekRaw);

    // 3. Wrap (Encrypt) the DEK using the Master Key (KEK)
    const wrappedDek = await encryptWithKey(dekRaw, masterKeyRaw);

    return {
        encrypted_private_key: uint8ArrayToBase64(encryptedPrivateKey),
        wrapped_dek: uint8ArrayToBase64(wrappedDek)
    };
}
```

## Why this is the "Gold Standard"

* Security at Rest: Even if an attacker steals your database, they cannot decrypt the private keys because they don't have the Master Key from your .env.
* Performance: You never send your large private keys to a Key Management Service (KMS); you only send the tiny 32-byte DEK to be wrapped.
* Auditability: In production, every time you "unwrap" a DEK using a Master Key in a service like AWS KMS, it creates an audit log entry. [1, 8, 9, 10, 11] 

## Storage update
Your PostgreSQL table should be updated to hold the wrapped key:

```sql
ALTER TABLE key_store ADD COLUMN wrapped_dek TEXT NOT NULL; -- Stores the encrypted DEK
```

Would you like the decryption function that reverses this hierarchy to retrieve the original private key?

[1] [https://medium.com](https://medium.com/@haridharanka20/your-sensitive-data-is-at-risk-heres-how-envelope-encryption-with-aws-kms-can-save-it-9f2bdfef7f3e)
[2] [https://www.freecodecamp.org](https://www.freecodecamp.org/news/envelope-encryption/)
[3] [https://docs.cloud.google.com](https://docs.cloud.google.com/sql/docs/postgres/client-side-encryption)
[4] [https://www.linkedin.com](https://www.linkedin.com/pulse/practical-cryptographic-operations-key-management-enterprise-bone-guaie)
[5] [https://blog.railway.com](https://blog.railway.com/p/envelope-encryption#:~:text=Deploy%20initial%20envelope%20encryption%20code%20%28does%20nothing,Run%20data%20migration%20to%20re%2Dencrypt%20all%20variables.)
[6] [https://developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey)
[7] [https://saiprasadnayak.medium.com](https://saiprasadnayak.medium.com/safeguarding-your-data-exploring-envelope-encryption-c4704d1fa9a9)
[8] [https://medium.com](https://medium.com/asecuritysite-when-bob-met-alice/encrypting-the-encryption-key-its-a-wrap-47ec84ec12f5)
[9] [https://terrazone.io](https://terrazone.io/nist-800-57/)
[10] [https://stackoverflow.com](https://stackoverflow.com/questions/8054503/storing-encrypted-data-in-postgres)
[11] [https://news.ycombinator.com](https://news.ycombinator.com/item?id=38173141)
