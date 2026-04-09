import { useCallback, useEffect, useMemo, useState } from "react";
import {
  createShareLink,
  listFileLogs,
  listMyFiles,
  revokeShareLink,
  uploadEncryptedFile,
} from "../lib/api";
import {
  decryptText,
  encryptBytes,
  encryptText,
  exportAesKeyBase64Url,
  generateAesKey,
  importAesKey,
  sha256Hex,
} from "../lib/crypto";
import { getFileKey, saveFileKey } from "../lib/keyring";

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) {
    return "N/A";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  return `${value.toFixed(value >= 100 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function buildPublicShareUrl(shareToken, fileId) {
  const key = getFileKey(fileId);
  if (!key) {
    return "";
  }
  return `${window.location.origin}/share/${shareToken}#k=${key}`;
}

export default function DashboardPage({ token, user, onLogout }) {
  const [files, setFiles] = useState([]);
  const [filesLoading, setFilesLoading] = useState(true);
  const [requestError, setRequestError] = useState("");

  const [uploadCandidate, setUploadCandidate] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState("");
  const [uploadInputVersion, setUploadInputVersion] = useState(0);

  const [shareForm, setShareForm] = useState({
    fileId: "",
    expiresInHours: "24",
    maxDownloads: "",
    password: "",
    oneTime: false,
  });
  const [shareSubmitting, setShareSubmitting] = useState(false);
  const [shareLink, setShareLink] = useState("");
  const [shareError, setShareError] = useState("");

  const [fileLogs, setFileLogs] = useState({});
  const [activeLogFileId, setActiveLogFileId] = useState("");
  const [revokingShareToken, setRevokingShareToken] = useState("");

  const [resolvedFileNames, setResolvedFileNames] = useState({});

  const fileCountLabel = useMemo(() => {
    if (files.length === 0) {
      return "No encrypted files yet";
    }
    if (files.length === 1) {
      return "1 encrypted file";
    }
    return `${files.length} encrypted files`;
  }, [files.length]);

  const hasFiles = files.length > 0;

  const refreshFiles = useCallback(
    async ({ withLoader = true } = {}) => {
      if (withLoader) {
        setFilesLoading(true);
      }
      setRequestError("");

      try {
        const result = await listMyFiles(token);
        setFiles(Array.isArray(result?.files) ? result.files : []);
      } catch (error) {
        if (error.status === 401) {
          onLogout();
          return;
        }
        setRequestError(error.message || "Unable to fetch file metadata.");
      } finally {
        if (withLoader) {
          setFilesLoading(false);
        }
      }
    },
    [onLogout, token],
  );

  useEffect(() => {
    refreshFiles();
  }, [refreshFiles]);

  useEffect(() => {
    if (files.length === 0) {
      if (!shareForm.fileId) {
        return;
      }

      setShareForm((current) => ({
        ...current,
        fileId: "",
      }));
      return;
    }

    const selectedExists = files.some((file) => file.id === shareForm.fileId);
    if (selectedExists) {
      return;
    }

    setShareForm((current) => ({
      ...current,
      fileId: files[0].id,
    }));
  }, [files, shareForm.fileId]);

  useEffect(() => {
    let cancelled = false;

    async function resolveNames() {
      const resolved = {};

      for (const file of files) {
        const keyMaterial = getFileKey(file.id);
        const fallbackName = `Encrypted asset ${file.id.slice(-8)}`;

        if (!keyMaterial) {
          resolved[file.id] = fallbackName;
          continue;
        }

        try {
          const cryptoKey = await importAesKey(keyMaterial);
          const plainName = await decryptText(
            cryptoKey,
            file.encryptedName,
            file.encryptedNameIv,
          );
          resolved[file.id] = plainName;
        } catch {
          resolved[file.id] = fallbackName;
        }
      }

      if (!cancelled) {
        setResolvedFileNames(resolved);
      }
    }

    resolveNames();

    return () => {
      cancelled = true;
    };
  }, [files]);

  async function handleEncryptedUpload(event) {
    event.preventDefault();
    setUploadStatus("");

    if (!uploadCandidate) {
      setUploadStatus("Select a file before uploading.");
      return;
    }

    setUploading(true);

    try {
      const cryptoKey = await generateAesKey();
      const exportedKey = await exportAesKeyBase64Url(cryptoKey);

      const clearFileBytes = new Uint8Array(await uploadCandidate.arrayBuffer());
      const encryptedFilePayload = await encryptBytes(cryptoKey, clearFileBytes);
      const encryptedNamePayload = await encryptText(cryptoKey, uploadCandidate.name);
      const ciphertextHash = await sha256Hex(encryptedFilePayload.cipherBytes);

      const formData = new FormData();
      formData.append(
        "encryptedFile",
        new Blob([encryptedFilePayload.cipherBytes], {
          type: "application/octet-stream",
        }),
        `${uploadCandidate.name}.enc`,
      );
      formData.append("encryptedName", encryptedNamePayload.cipherTextBase64);
      formData.append("encryptedNameIv", encryptedNamePayload.ivBase64);
      formData.append("encryptedFileIv", encryptedFilePayload.ivBase64);
      formData.append("fileHash", ciphertextHash);
      formData.append("cipherAlgorithm", "AES-GCM");
      formData.append("mimeType", uploadCandidate.type || "application/octet-stream");
      formData.append("originalSize", String(uploadCandidate.size));

      const result = await uploadEncryptedFile(token, formData);
      const uploadedFile = result?.file;

      if (!uploadedFile?.id) {
        throw new Error("Server did not return file metadata after upload.");
      }

      saveFileKey(uploadedFile.id, exportedKey);
      setUploadStatus("Upload complete. Only encrypted data was sent to the server.");
      setUploadCandidate(null);
      setUploadInputVersion((value) => value + 1);
      setShareForm((current) => ({
        ...current,
        fileId: uploadedFile.id,
      }));
      await refreshFiles({ withLoader: false });
    } catch (error) {
      setUploadStatus(error.message || "Encrypted upload failed.");
    } finally {
      setUploading(false);
    }
  }

  async function handleShareCreation(event) {
    event.preventDefault();
    setShareError("");
    setShareLink("");

    if (!hasFiles) {
      setShareError("No encrypted files found. Upload one first, then create the share link.");
      return;
    }

    if (!shareForm.fileId) {
      setShareError("Select a file to generate a share link.");
      return;
    }

    if (shareForm.password.trim() && shareForm.password.trim().length < 6) {
      setShareError("Share password must be at least 6 characters.");
      return;
    }

    const keyMaterial = getFileKey(shareForm.fileId);
    if (!keyMaterial) {
      setShareError(
        "Local key is missing for this file. Without it, you cannot generate a decryptable link.",
      );
      return;
    }

    const payload = {
      oneTime: shareForm.oneTime,
    };

    if (shareForm.expiresInHours) {
      payload.expiresInHours = Number(shareForm.expiresInHours);
    }

    if (shareForm.maxDownloads) {
      payload.maxDownloads = Number(shareForm.maxDownloads);
    }

    if (shareForm.password.trim()) {
      payload.password = shareForm.password.trim();
    }

    setShareSubmitting(true);

    try {
      const result = await createShareLink(token, shareForm.fileId, payload);
      const fullUrl = `${window.location.origin}${result.publicPath}#k=${keyMaterial}`;
      setShareLink(fullUrl);
      await navigator.clipboard.writeText(fullUrl).catch(() => null);
      await refreshFiles({ withLoader: false });
    } catch (error) {
      setShareError(error.message || "Unable to create secure share link.");
    } finally {
      setShareSubmitting(false);
    }
  }

  async function handleRevokeShare(shareToken) {
    setRevokingShareToken(shareToken);
    setRequestError("");

    try {
      await revokeShareLink(token, shareToken);
      await refreshFiles({ withLoader: false });
    } catch (error) {
      setRequestError(error.message || "Unable to revoke share link.");
    } finally {
      setRevokingShareToken("");
    }
  }

  async function handleLoadLogs(fileId) {
    setActiveLogFileId(fileId);

    try {
      const result = await listFileLogs(token, fileId);
      setFileLogs((current) => ({
        ...current,
        [fileId]: Array.isArray(result?.logs) ? result.logs : [],
      }));
    } catch (error) {
      setRequestError(error.message || "Unable to load access logs.");
    } finally {
      setActiveLogFileId("");
    }
  }

  return (
    <main className="page dashboard-page">
      <header className="dashboard-header reveal-up">
        <div>
          <p className="eyebrow">VaultMesh Zero-Knowledge Workspace</p>
          <h1>Secure file operations</h1>
          <p className="muted">
            Signed in as <strong>{user?.name || user?.email || "User"}</strong>.
            Encryption keys remain in your browser storage.
          </p>
        </div>
        <button className="btn ghost" type="button" onClick={onLogout}>
          Logout
        </button>
      </header>

      {requestError ? <p className="status error reveal-up">{requestError}</p> : null}

      <section className="grid-two">
        <article className="panel reveal-up">
          <h2>Encrypt and upload</h2>
          <p className="muted">
            The selected file is encrypted in-browser using AES-GCM before transmission.
          </p>
          <form className="form-grid" onSubmit={handleEncryptedUpload}>
            <label>
              Choose file
              <input
                key={uploadInputVersion}
                type="file"
                onChange={(event) => setUploadCandidate(event.target.files?.[0] || null)}
                required
              />
            </label>
            <button className="btn primary" type="submit" disabled={uploading}>
              {uploading ? "Encrypting..." : "Encrypt and upload"}
            </button>
            {uploadStatus ? <p className="status">{uploadStatus}</p> : null}
          </form>
        </article>

        <article className="panel reveal-up">
          <h2>Create secure share link</h2>
          <p className="muted">
            Link key is placed in the URL fragment so the server never receives it.
          </p>
          <button
            className="btn ghost"
            type="button"
            disabled={filesLoading || shareSubmitting}
            onClick={() => refreshFiles({ withLoader: true })}
          >
            {filesLoading ? "Refreshing..." : "Refresh file list"}
          </button>
          <form className="form-grid" onSubmit={handleShareCreation}>
            <label>
              File
              <select
                value={shareForm.fileId}
                disabled={!hasFiles}
                onChange={(event) =>
                  setShareForm((current) => ({
                    ...current,
                    fileId: event.target.value,
                  }))
                }
              >
                <option value="" disabled>
                  {hasFiles ? "Select encrypted file" : "No encrypted file available"}
                </option>
                {files.map((file) => (
                  <option value={file.id} key={file.id}>
                    {resolvedFileNames[file.id] || file.id}
                  </option>
                ))}
              </select>
            </label>

            {!hasFiles ? (
              <p className="status">Upload an encrypted file first to enable secure sharing.</p>
            ) : null}

            <label>
              Expires in hours
              <input
                type="number"
                min="1"
                max="8760"
                value={shareForm.expiresInHours}
                onChange={(event) =>
                  setShareForm((current) => ({
                    ...current,
                    expiresInHours: event.target.value,
                  }))
                }
                placeholder="24"
              />
            </label>

            <label>
              Max downloads
              <input
                type="number"
                min="1"
                value={shareForm.maxDownloads}
                onChange={(event) =>
                  setShareForm((current) => ({
                    ...current,
                    maxDownloads: event.target.value,
                  }))
                }
                placeholder="Unlimited"
              />
            </label>

            <label>
              Optional password
              <input
                type="text"
                value={shareForm.password}
                onChange={(event) =>
                  setShareForm((current) => ({
                    ...current,
                    password: event.target.value,
                  }))
                }
                minLength={6}
                placeholder="Add extra access password"
              />
            </label>

            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={shareForm.oneTime}
                onChange={(event) =>
                  setShareForm((current) => ({
                    ...current,
                    oneTime: event.target.checked,
                  }))
                }
              />
              One-time download only
            </label>

            {shareError ? <p className="status error">{shareError}</p> : null}

            <button
              className="btn primary"
              type="submit"
              disabled={shareSubmitting || !hasFiles}
            >
              {shareSubmitting ? "Generating..." : "Create encrypted link"}
            </button>
          </form>

          {shareLink ? (
            <div className="share-link-box">
              <p className="muted">Copied to clipboard:</p>
              <p className="mono break-all">{shareLink}</p>
            </div>
          ) : null}
        </article>
      </section>

      <section className="panel reveal-up">
        <div className="panel-header">
          <h2>Encrypted assets</h2>
          <p className="muted">{fileCountLabel}</p>
        </div>

        {filesLoading ? <p className="status">Loading encrypted metadata...</p> : null}

        {!filesLoading && files.length === 0 ? (
          <p className="status">Upload your first encrypted file to begin sharing.</p>
        ) : null}

        <div className="files-stack">
          {files.map((file) => (
            <article className="file-card" key={file.id}>
              <div className="file-row">
                <div>
                  <h3>{resolvedFileNames[file.id] || "Encrypted file"}</h3>
                  <p className="mono">{file.id}</p>
                </div>
                <p className="muted">
                  {formatBytes(file.size)} encrypted • {file.cipherAlgorithm}
                </p>
              </div>

              <p className="muted">
                Uploaded: {new Date(file.createdAt).toLocaleString()} • Hash: {file.fileHash.slice(0, 16)}...
              </p>

              <div className="share-list">
                {file.shares?.length ? (
                  file.shares.map((share) => {
                    const publicUrl = buildPublicShareUrl(share.token, file.id);
                    const isDisabled = share.revoked;

                    return (
                      <div className="share-item" key={share.token}>
                        <p className="mono">{share.token}</p>
                        <p className="muted">
                          {share.passwordProtected ? "Password" : "No password"} • downloads {share.downloadCount}
                          {Number.isInteger(share.maxDownloads)
                            ? `/${share.maxDownloads}`
                            : " / unlimited"}
                          {share.oneTime ? " • one-time" : ""}
                          {share.expiresAt
                            ? ` • expires ${new Date(share.expiresAt).toLocaleString()}`
                            : " • no expiry"}
                        </p>
                        {publicUrl ? <p className="mono break-all">{publicUrl}</p> : null}
                        <button
                          className="btn danger"
                          type="button"
                          disabled={isDisabled || revokingShareToken === share.token}
                          onClick={() => handleRevokeShare(share.token)}
                        >
                          {isDisabled
                            ? "Revoked"
                            : revokingShareToken === share.token
                              ? "Revoking..."
                              : "Revoke"}
                        </button>
                      </div>
                    );
                  })
                ) : (
                  <p className="status">No share links yet.</p>
                )}
              </div>

              <div className="logs-section">
                <button
                  className="btn ghost"
                  type="button"
                  disabled={activeLogFileId === file.id}
                  onClick={() => handleLoadLogs(file.id)}
                >
                  {activeLogFileId === file.id ? "Loading logs..." : "Load access logs"}
                </button>

                {fileLogs[file.id]?.length ? (
                  <div className="log-list">
                    {fileLogs[file.id].map((logEntry) => (
                      <p key={logEntry.id} className="mono">
                        {new Date(logEntry.createdAt).toLocaleString()} | {logEntry.status} | {logEntry.reason} | {logEntry.ip}
                      </p>
                    ))}
                  </div>
                ) : null}
              </div>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
