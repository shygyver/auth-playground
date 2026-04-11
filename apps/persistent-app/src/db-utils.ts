/**
 * Converts a Uint8Array to a Base64 string
 */
export function uint8ArrayToBase64(uint8: Uint8Array): string {
    if (uint8.toBase64) {
        return uint8.toBase64();
    }
    // Converts binary bytes to a string of characters (0-255) then to Base64
    return btoa(String.fromCharCode(...uint8));
}

/**
 * Converts a Base64 string back to a Uint8Array
 */
export function base64ToUint8Array(base64: string): Uint8Array {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}