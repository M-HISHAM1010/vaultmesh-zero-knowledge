const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

async function parseErrorResponse(response) {
  const contentType = response.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    const payload = await response.json().catch(() => null);
    if (payload?.message) {
      return payload.message;
    }
  }

  const text = await response.text().catch(() => "");
  if (text) {
    return text;
  }

  return `Request failed with status ${response.status}`;
}

async function parseJsonResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    return null;
  }
  return response.json();
}

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, options);

  if (!response.ok) {
    const message = await parseErrorResponse(response);
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return parseJsonResponse(response);
}

function createAuthHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
  };
}

export async function registerUser(payload) {
  return apiRequest("/api/auth/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function loginUser(payload) {
  return apiRequest("/api/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function listMyFiles(token) {
  return apiRequest("/api/files", {
    method: "GET",
    headers: createAuthHeaders(token),
  });
}

export async function uploadEncryptedFile(token, formData) {
  return apiRequest("/api/files/upload", {
    method: "POST",
    headers: createAuthHeaders(token),
    body: formData,
  });
}

export async function createShareLink(token, fileId, payload) {
  return apiRequest(`/api/files/${fileId}/shares`, {
    method: "POST",
    headers: {
      ...createAuthHeaders(token),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function revokeShareLink(token, shareToken) {
  return apiRequest(`/api/shares/${shareToken}/revoke`, {
    method: "POST",
    headers: createAuthHeaders(token),
  });
}

export async function listFileLogs(token, fileId) {
  return apiRequest(`/api/files/${fileId}/logs`, {
    method: "GET",
    headers: createAuthHeaders(token),
  });
}

export async function getShareInfo(shareToken) {
  return apiRequest(`/api/shares/${shareToken}/info`, {
    method: "GET",
  });
}

export async function downloadSharedCiphertext(shareToken, password) {
  const response = await fetch(`${API_BASE_URL}/api/shares/${shareToken}/download`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ password: password || "" }),
  });

  if (!response.ok) {
    const message = await parseErrorResponse(response);
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  const blob = await response.blob();
  return {
    blob,
    headers: {
      fileHash: response.headers.get("x-file-hash") || "",
      encryptedName: response.headers.get("x-encrypted-name") || "",
      encryptedNameIv: response.headers.get("x-encrypted-name-iv") || "",
      encryptedFileIv: response.headers.get("x-encrypted-file-iv") || "",
      cipherAlgorithm: response.headers.get("x-cipher-algorithm") || "",
      originalMimeType: response.headers.get("x-original-mime-type") || "application/octet-stream",
    },
  };
}
