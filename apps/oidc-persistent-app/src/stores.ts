import {
  getPrivateKeyCreatedAt,
  getPrivateKeyRecord,
  getPublicKeyRecords,
  PrivateKeyRecord,
  PublicKeyRecord,
  saveKeyPairRecord,
} from "./db";
import { JwksKeyStore, JwksRotationTimestampStore } from "@saurbit/oauth2-jwt";

/**
 * In a production environment, the master key (KEK) should be stored securely,
 * such as in an environment variable or a secrets manager.
 * It should never be hardcoded in the source code.
 * This should be a base64-encoded 32-byte key (256 bits) for AES-256 encryption.
 */
const ENV_MASTER_KEY = process.env.MASTER_KEY!;

/**
 * 256-bit master key (KEK) for encrypting the DEK (Data Encryption Key).
 */
const MASTER_KEY_RAW = base64ToUint8Array(ENV_MASTER_KEY);

/**
 * Converts a Uint8Array to a Base64 string
 */
function uint8ArrayToBase64(uint8: Uint8Array): string {
  if (uint8.toBase64) {
    return uint8.toBase64();
  }
  // Converts binary bytes to a string of characters (0-255) then to Base64
  return btoa(String.fromCharCode(...uint8));
}

/**
 * Converts a Base64 string back to a Uint8Array
 */
function base64ToUint8Array(base64: string): Uint8Array<ArrayBuffer> {
  if (Uint8Array.fromBase64) {
    return Uint8Array.fromBase64(base64);
  }
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encrypts plaintext using AES-GCM with the provided raw key.
 *
 * @param plaintext The plaintext string to be encrypted.
 * @param rawKey The raw key (BufferSource) used for encryption.
 * @returns A Uint8Array containing the IV and ciphertext.
 */
async function encrypt(plaintext: string, rawKey: BufferSource): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);

  // Import the raw key (32 bytes for AES-256)
  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"]);

  // Generate a random 12-byte IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the data
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, data);

  // Combine IV and ciphertext for storage (IV must be saved to decrypt)
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return combined;
}

/**
 * Decrypts ciphertext using AES-GCM with the provided raw key.
 *
 * @param combinedData A Uint8Array containing the IV and ciphertext.
 * @param rawKey The raw key (BufferSource) used for decryption.
 * @returns The decrypted plaintext string.
 */
async function decrypt(combinedData: Uint8Array, rawKey: BufferSource): Promise<string> {
  // Split the IV (first 12 bytes) and the ciphertext
  const iv = combinedData.slice(0, 12);
  const ciphertext = combinedData.slice(12);

  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);

  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ciphertext);

  return new TextDecoder().decode(decrypted);
}

/**
 * Implements the JwksKeyStore interface for managing JWKS keys with encryption and secure storage.
 * The private keys are encrypted using a DEK (Data Encryption Key), which is itself encrypted with a master key (KEK) before storage.
 * This ensures that even if the database is compromised, the private keys remain protected.
 */
export const jwksStore: JwksKeyStore = {
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
      wrappedDek: uint8ArrayToBase64(wrappedDek),
    };
    const publicKeyRecord: PublicKeyRecord = {
      keyId: kid,
      publicKey: JSON.stringify(publicKey),
    };

    await saveKeyPairRecord(privateKeyRecord, publicKeyRecord, expirationTime);
  },
  async getPublicKeys(): Promise<object[]> {
    const publicKeyRecords = await getPublicKeyRecords();
    if (!publicKeyRecords) {
      return [];
    }
    return publicKeyRecords.map((record) => JSON.parse(record.publicKey));
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
    const decryptedPrivateKeyString = await decrypt(
      base64ToUint8Array(privateKeyRecord.privateKey),
      dekRaw
    );

    return JSON.parse(decryptedPrivateKeyString);
  },
};

/**
 * Implements the JwksRotationTimestampStore interface for managing JWKS rotation timestamps.
 * This store keeps track of the last rotation timestamp.
 */
export const rotationTimestampStore: JwksRotationTimestampStore = {
  async getLastRotationTimestamp(): Promise<number> {
    const createdAt = await getPrivateKeyCreatedAt();
    if (!createdAt) {
      return 0; // No keys have been created yet, so we can consider the last rotation timestamp as 0
    }
    return createdAt.getTime(); // Return the timestamp of the last key creation
  },
  async setLastRotationTimestamp(timestamp: number): Promise<void> {
    // In this implementation, we don't need to explicitly set the rotation timestamp,
    // because we can derive it from the created_at field of the private key record.
    // However, if you want to implement a separate mechanism for tracking rotation timestamps,
    // you could add a new table in the database and implement the logic here to store and retrieve it.
  },
};
