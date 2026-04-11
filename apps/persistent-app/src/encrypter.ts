export async function encrypt(plaintext: string, rawKey: BufferSource) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    
    // Import the raw key (32 bytes for AES-256)
    const key = await crypto.subtle.importKey(
        "raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"]
    );

    // Generate a random 12-byte IV
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the data
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, key, data
    );

    // Combine IV and ciphertext for storage (IV must be saved to decrypt)
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), iv.length);
    
    return combined;
}

export async function decrypt(combinedData: Uint8Array, rawKey: BufferSource) {
    // Split the IV (first 12 bytes) and the ciphertext
    const iv = combinedData.slice(0, 12);
    const ciphertext = combinedData.slice(12);

    const key = await crypto.subtle.importKey(
        "raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv }, key, ciphertext
    );

    return new TextDecoder().decode(decrypted);
}

export async function generateNewRawKey() {
    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true, // extractable
        ["encrypt", "decrypt"]
    );
    
    // Export it to a Uint8Array (32 bytes)
    const rawKeyExported = await crypto.subtle.exportKey("raw", key);
    return new Uint8Array(rawKeyExported);
}