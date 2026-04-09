const KEYRING_STORAGE_KEY = "zkfs_keyring_v1";

function readKeyring() {
  const raw = localStorage.getItem(KEYRING_STORAGE_KEY);
  if (!raw) {
    return {};
  }

  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      return parsed;
    }
    return {};
  } catch {
    return {};
  }
}

function writeKeyring(keyring) {
  localStorage.setItem(KEYRING_STORAGE_KEY, JSON.stringify(keyring));
}

export function saveFileKey(fileId, keyBase64Url) {
  const keyring = readKeyring();
  keyring[fileId] = keyBase64Url;
  writeKeyring(keyring);
}

export function getFileKey(fileId) {
  const keyring = readKeyring();
  return keyring[fileId] || "";
}

export function removeFileKey(fileId) {
  const keyring = readKeyring();
  delete keyring[fileId];
  writeKeyring(keyring);
}
