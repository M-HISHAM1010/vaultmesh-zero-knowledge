const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function bytesToBinary(bytes) {
  const chunkSize = 0x8000;
  let output = "";
  for (let index = 0; index < bytes.length; index += chunkSize) {
    const chunk = bytes.subarray(index, index + chunkSize);
    output += String.fromCharCode(...chunk);
  }
  return output;
}

export function bytesToBase64(bytes) {
  return btoa(bytesToBinary(bytes));
}

export function base64ToBytes(base64Value) {
  const binary = atob(base64Value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function base64UrlToBytes(base64Url) {
  const normalized = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = (4 - (normalized.length % 4)) % 4;
  const padded = `${normalized}${"=".repeat(paddingLength)}`;
  return base64ToBytes(padded);
}

function createIv() {
  return crypto.getRandomValues(new Uint8Array(12));
}

export async function generateAesKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}

export async function exportAesKeyBase64Url(key) {
  const rawKey = await crypto.subtle.exportKey("raw", key);
  return bytesToBase64Url(new Uint8Array(rawKey));
}

export async function importAesKey(base64UrlKey) {
  const raw = base64UrlToBytes(base64UrlKey);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function encryptBytes(key, plainBytes) {
  const iv = createIv();
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    plainBytes,
  );

  return {
    cipherBytes: new Uint8Array(encrypted),
    ivBase64: bytesToBase64(iv),
  };
}

export async function decryptBytes(key, cipherBytes, ivBase64) {
  const iv = base64ToBytes(ivBase64);
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    cipherBytes,
  );
  return new Uint8Array(decrypted);
}

export async function encryptText(key, plainText) {
  const inputBytes = textEncoder.encode(plainText);
  const encrypted = await encryptBytes(key, inputBytes);
  return {
    cipherTextBase64: bytesToBase64(encrypted.cipherBytes),
    ivBase64: encrypted.ivBase64,
  };
}

export async function decryptText(key, cipherTextBase64, ivBase64) {
  const cipherBytes = base64ToBytes(cipherTextBase64);
  const plainBytes = await decryptBytes(key, cipherBytes, ivBase64);
  return textDecoder.decode(plainBytes);
}

export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hashArray = Array.from(new Uint8Array(digest));
  return hashArray.map((item) => item.toString(16).padStart(2, "0")).join("");
}

export function triggerBrowserDownload(blob, fileName) {
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(objectUrl);
}
