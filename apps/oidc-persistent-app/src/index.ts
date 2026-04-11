import {
  JoseJwksAuthority,
  JwksKeyStore,
  JwksRotationTimestampStore,
  JwksRotator
} from "@saurbit/oauth2-jwt";
import { decrypt, encrypt } from "./encrypter";
import { base64ToUint8Array, uint8ArrayToBase64 } from "./utils";
import { getPrivateKeyRecord, getPublicKeyRecords, PrivateKeyRecord, PublicKeyRecord, saveKeyPairRecord } from "./db";

/**
 * In a production environment, the master key (KEK) should be stored securely, 
 * such as in an environment variable or a secrets manager. 
 * It should never be hardcoded in the source code. 
 * For demonstration purposes, we are using a hardcoded base64-encoded key here, 
 * but this is not recommended for real applications.
 */
const ENV_MASTER_KEY = "XbHLNmLgESjwXtRkRVd5MsxEsl/zmvJLEdJ7cx42E9s="; 

/**
 * 256-bit master key (KEK) for encrypting the DEK (Data Encryption Key).
 */
const MASTER_KEY_RAW = base64ToUint8Array(ENV_MASTER_KEY);

// console.log("MASTER_KEY_RAW (Base64):", crypto.getRandomValues(new Uint8Array(32)).toBase64());


const jwksStore: JwksKeyStore = {
  async storeKeyPair(kid: string, privateKey: object, publicKey: object, ttl: number) {
    // 1. Generate a fresh, unique DEK (Data Encryption Key)
    const dekRaw = crypto.getRandomValues(new Uint8Array(32));

    // 2. Encrypt the Private Key with the DEK
    const encryptedPrivateKey = await encrypt(JSON.stringify(privateKey), dekRaw);

    // 3. Wrap (Encrypt) the DEK using the Master Key (KEK)
    const wrappedDek = await encrypt(uint8ArrayToBase64(dekRaw), MASTER_KEY_RAW);

    // 4. Store the encrypted private key and the wrapped DEK together
    const expirationTime = Date.now() + ttl * 1000; // Calculate expiration time in milliseconds
    const privateKeyRecord: PrivateKeyRecord = {
      keyId: kid,
      privateKey: uint8ArrayToBase64(encryptedPrivateKey),
      wrappedDek: uint8ArrayToBase64(wrappedDek)
    };
    const publicKeyRecord: PublicKeyRecord = {
      keyId: kid,
      publicKey: JSON.stringify(publicKey)
    };

    await saveKeyPairRecord(privateKeyRecord, publicKeyRecord, expirationTime);
  },
  async getPublicKeys(): Promise<object[]> {
    const publicKeyRecords = await getPublicKeyRecords();
    if (!publicKeyRecords) {
      return [];
    }
    return publicKeyRecords.map(record => JSON.parse(record.publicKey));
  },
  async getPrivateKey(): Promise<object | undefined> {
    const privateKeyRecord = await getPrivateKeyRecord();
    if (!privateKeyRecord) {
      return undefined; // No valid private key found
    }

    // 1. Unwrap (Decrypt) the DEK using the Master Key (KEK)
    const wrappedDekBytes = base64ToUint8Array(privateKeyRecord.wrappedDek);
    const dekRawString = await decrypt(wrappedDekBytes, MASTER_KEY_RAW);
    const dekRaw = base64ToUint8Array(dekRawString);

    // 2. Decrypt the Private Key using the DEK
    const decryptedPrivateKeyString = await decrypt(base64ToUint8Array(privateKeyRecord.privateKey), dekRaw);

    return JSON.parse(decryptedPrivateKeyString);
  }
}

const rotatorKeyStore: JwksRotationTimestampStore = {
  async getLastRotationTimestamp(): Promise<number> {
    // Implement logic to retrieve the last rotation timestamp from your storage (e.g., database, file, etc.)
    // For demonstration, we return a fixed timestamp. In production, this should be dynamic.
    return Date.now() - 9 * 24 * 60 * 60 * 1000; // Simulate last rotation was 9 days ago
  },
  async setLastRotationTimestamp(timestamp: number): Promise<void> {
    // Implement logic to save the last rotation timestamp to your storage (e.g., database, file, etc.) for future reference.
    // For demonstration, we simply log it. In production, this should persist the timestamp.
    console.log("Setting last rotation timestamp to:", new Date(timestamp).toISOString());
  } 
}

const jwksAuthority = new JoseJwksAuthority(jwksStore, 8.64e6); // 100-day key lifetime

await jwksAuthority.generateKeyPair()

const jwksRotator = new JwksRotator({
  keyGenerator:jwksAuthority,
  rotatorKeyStore: rotatorKeyStore,
  rotationIntervalMs: 7.884e9, // 91 days
});