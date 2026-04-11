import {
  JoseJwksAuthority,
  JwksKeyStore
} from "@saurbit/oauth2-jwt";
import { encrypt } from "./encrypter";
import { base64ToUint8Array, uint8ArrayToBase64 } from "./utils";
import { saveKeyPair } from "./db";

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
    const wrappedDek = await encrypt(JSON.stringify(dekRaw), MASTER_KEY_RAW);

    // 4. Store the encrypted private key and the wrapped DEK together
    const expirationTime = Date.now() + ttl * 1000; // Calculate expiration time in milliseconds
    const privateObject = {
      keyId: kid,
      privateKey: uint8ArrayToBase64(encryptedPrivateKey),
      wrappedDek: uint8ArrayToBase64(wrappedDek)
    };
    const publicObject = {
      keyId: kid,
      publicKey: JSON.stringify(publicKey)
    };
    await saveKeyPair(privateObject, publicObject, expirationTime);
  },
  async getPublicKeys(): Promise<object[]> {
    // This method should return an array of public keys in JWK format
    // For simplicity, we will return an empty array here. In a real implementation, you would retrieve the stored keys and return their public parts.
    return [];
  },
  async getPrivateKey(): Promise<object | undefined> {
    // This method should retrieve the encrypted private key and wrapped DEK for the given kid, unwrap the DEK, decrypt the private key, and return it as an object.
    // For simplicity, we will return undefined here. In a real implementation, you would look up the storage for the given kid, perform the decryption steps, and return the private key.
    return undefined;
  }
}

const jwksAuthority = new JoseJwksAuthority(jwksStore, 8.64e6); // 100-day key lifetime

jwksAuthority.generateKeyPair()