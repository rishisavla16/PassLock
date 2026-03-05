// secure_password_manager/static/crypto.js

// --- Configuration ---
// Security: A high iteration count is crucial to slow down brute-force attacks on the master password.
// 100,000 is a minimum; 300,000 or more is recommended.
const PBKDF2_ITERATIONS = 310000; 
const PBKDF2_SALT_LENGTH = 16; // in bytes
const AES_IV_LENGTH = 12; // in bytes, 96 bits is recommended for GCM

// --- Helper Functions for ArrayBuffer/String/Base64 conversions ---

// Converts a string to an ArrayBuffer
function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

// Converts an ArrayBuffer to a string
function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}

// Converts an ArrayBuffer to a Base64 string
function ab2b64(arr) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(arr)));
}

// Converts a Base64 string to an ArrayBuffer
function b642ab(b64) {
    return str2ab(atob(b64));
}

// --- Core Cryptographic Functions ---

/**
 * Derives an encryption key from a master password and a salt using PBKDF2.
 * @param {string} password - The user's master password.
 * @param {Uint8Array} salt - The salt for key derivation.
 * @returns {Promise<CryptoKey>} A promise that resolves to the derived CryptoKey for AES-GCM.
 */
async function deriveKey(password, salt) {
    // Security: Using PBKDF2, a standard key derivation function.
    const passwordBuffer = str2ab(password);
    
    // 1. Import the master password as a base key.
    const baseKey = await window.crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    // 2. Derive the AES-GCM key.
    // Security: SHA-256 is a secure hash function.
    const derivedKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        baseKey,
        { name: "AES-GCM", length: 256 }, // Key algorithm and length
        true, // Key is extractable (false is better if not needed)
        ["encrypt", "decrypt"] // Key usages
    );

    return derivedKey;
}

/**
 * Encrypts data using AES-256-GCM.
 * @param {string} plaintext - The data to encrypt (e.g., a JSON string).
 * @param {CryptoKey} key - The encryption key from deriveKey.
 * @returns {Promise<string>} A promise that resolves to a Base64 encoded string of "IV + Ciphertext".
 */
async function encrypt(plaintext, key) {
    const dataBuffer = str2ab(plaintext);
    
    // Security: A unique, random IV (Initialization Vector) must be used for each encryption.
    // Reusing an IV with GCM is catastrophic.
    const iv = window.crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));

    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        dataBuffer
    );

    // Security: Prepend the IV to the ciphertext. This is standard practice.
    // The IV is not secret, but it must be unique and authentic. GCM includes the IV
    // in its authenticity calculations.
    const ivAndCiphertext = new Uint8Array(iv.length + ciphertext.byteLength);
    ivAndCiphertext.set(iv);
    ivAndCiphertext.set(new Uint8Array(ciphertext), iv.length);

    return ab2b64(ivAndCiphertext);
}

/**
 * Decrypts data using AES-256-GCM.
 * @param {string} encryptedBase64 - The Base64 encoded "IV + Ciphertext".
 * @param {CryptoKey} key - The decryption key from deriveKey.
 * @returns {Promise<string>} A promise that resolves to the decrypted plaintext.
 * Throws an error if decryption fails (e.g., wrong key, tampered data).
 */
async function decrypt(encryptedBase64, key) {
    const ivAndCiphertext = b642ab(encryptedBase64);

    // Extract the IV from the beginning of the data.
    const iv = ivAndCiphertext.slice(0, AES_IV_LENGTH);
    const ciphertext = ivAndCiphertext.slice(AES_IV_LENGTH);

    try {
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            key,
            ciphertext
        );
        // Security: If decryption succeeds, it means the key was correct AND the data
        // was not tampered with, thanks to the GCM authentication tag.
        return ab2str(decryptedBuffer);
    } catch (e) {
        // Decryption failed. This is the expected result for a wrong master password.
        console.error("Decryption failed:", e);
        throw new Error("Decryption failed. Incorrect master password or corrupted data.");
    }
}
