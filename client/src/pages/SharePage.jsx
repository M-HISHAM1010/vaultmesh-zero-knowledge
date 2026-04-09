import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { downloadSharedCiphertext, getShareInfo } from "../lib/api";
import {
  decryptBytes,
  decryptText,
  importAesKey,
  sha256Hex,
  triggerBrowserDownload,
} from "../lib/crypto";

function extractKeyFromFragment(hashValue) {
  const rawHash = (hashValue || "").replace(/^#/, "").trim();
  if (!rawHash) {
    return "";
  }

  const params = new URLSearchParams(rawHash);
  const keyed = params.get("k");
  if (keyed) {
    return keyed;
  }

  if (!rawHash.includes("=")) {
    return rawHash;
  }

  return "";
}

function formatDate(value) {
  if (!value) {
    return "Not set";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "Invalid date";
  }

  return parsed.toLocaleString();
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) {
    return "N/A";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let unit = 0;

  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }

  return `${size.toFixed(size >= 100 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export default function SharePage() {
  const { token } = useParams();
  const [fragmentKey, setFragmentKey] = useState(() => extractKeyFromFragment(window.location.hash));

  const [shareInfo, setShareInfo] = useState(null);
  const [loadingInfo, setLoadingInfo] = useState(true);
  const [error, setError] = useState("");

  const [password, setPassword] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [downloadStatus, setDownloadStatus] = useState("");

  const keyMissing = useMemo(() => !fragmentKey, [fragmentKey]);

  useEffect(() => {
    function onHashChange() {
      setFragmentKey(extractKeyFromFragment(window.location.hash));
    }

    window.addEventListener("hashchange", onHashChange);
    return () => {
      window.removeEventListener("hashchange", onHashChange);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadShareInfo() {
      setLoadingInfo(true);
      setError("");

      try {
        const result = await getShareInfo(token);
        if (!cancelled) {
          setShareInfo(result);
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError.message || "Unable to load share metadata.");
        }
      } finally {
        if (!cancelled) {
          setLoadingInfo(false);
        }
      }
    }

    loadShareInfo();

    return () => {
      cancelled = true;
    };
  }, [token]);

  async function handleSecureDownload() {
    setDownloadStatus("");

    if (!fragmentKey) {
      setDownloadStatus("Missing decryption key in URL fragment.");
      return;
    }

    setDownloading(true);

    try {
      const cryptoKey = await importAesKey(fragmentKey);
      const encryptedResponse = await downloadSharedCiphertext(token, password);
      const encryptedBytes = new Uint8Array(await encryptedResponse.blob.arrayBuffer());

      const calculatedHash = await sha256Hex(encryptedBytes);
      if (
        encryptedResponse.headers.fileHash &&
        calculatedHash !== encryptedResponse.headers.fileHash
      ) {
        throw new Error("Integrity check failed. Ciphertext hash mismatch.");
      }

      if (!encryptedResponse.headers.encryptedFileIv) {
        throw new Error("Share metadata is incomplete. Missing file IV.");
      }

      const plainBytes = await decryptBytes(
        cryptoKey,
        encryptedBytes,
        encryptedResponse.headers.encryptedFileIv,
      );

      let fileName = `decrypted-${token}.bin`;
      if (
        encryptedResponse.headers.encryptedName &&
        encryptedResponse.headers.encryptedNameIv
      ) {
        try {
          fileName = await decryptText(
            cryptoKey,
            encryptedResponse.headers.encryptedName,
            encryptedResponse.headers.encryptedNameIv,
          );
        } catch {
          // Keep fallback filename when name decryption fails.
        }
      }

      const blob = new Blob([plainBytes], {
        type: encryptedResponse.headers.originalMimeType || "application/octet-stream",
      });

      triggerBrowserDownload(blob, fileName);
      setDownloadStatus("File decrypted and downloaded successfully.");

      const updatedInfo = await getShareInfo(token).catch(() => null);
      if (updatedInfo) {
        setShareInfo(updatedInfo);
      }
    } catch (downloadError) {
      setDownloadStatus(downloadError.message || "Secure download failed.");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <main className="page share-page">
      <section className="hero-panel reveal-up">
        <p className="eyebrow">Zero-Knowledge Shared File</p>
        <h1>Decrypt in your browser</h1>
        <p className="hero-copy">
          The server transmits only ciphertext. This page decrypts data locally using
          the key in your URL fragment.
        </p>
      </section>

      <section className="panel reveal-up">
        {loadingInfo ? <p className="status">Loading share details...</p> : null}

        {error ? <p className="status error">{error}</p> : null}

        {shareInfo ? (
          <div className="share-metadata">
            <p>
              <strong>Algorithm:</strong> {shareInfo.file.cipherAlgorithm}
            </p>
            <p>
              <strong>Encrypted size:</strong> {formatBytes(shareInfo.file.size)}
            </p>
            <p>
              <strong>Expires:</strong> {formatDate(shareInfo.share.expiresAt)}
            </p>
            <p>
              <strong>Downloads:</strong> {shareInfo.share.downloadCount}
              {Number.isInteger(shareInfo.share.maxDownloads)
                ? ` / ${shareInfo.share.maxDownloads}`
                : " / unlimited"}
            </p>
            <p>
              <strong>Password required:</strong> {shareInfo.share.requiresPassword ? "Yes" : "No"}
            </p>
            <p>
              <strong>One-time:</strong> {shareInfo.share.oneTime ? "Yes" : "No"}
            </p>
            <p>
              <strong>Status:</strong> {shareInfo.share.disabled ? "Unavailable" : "Ready"}
            </p>
          </div>
        ) : null}

        {keyMissing ? (
          <p className="status error">
            Missing key fragment. Ask the sender for a full link containing #k=...
          </p>
        ) : (
          <p className="status">Decryption key detected in URL fragment.</p>
        )}

        {shareInfo?.share?.requiresPassword ? (
          <label>
            Share password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
        ) : null}

        <button
          className="btn primary"
          type="button"
          disabled={
            downloading || keyMissing || !shareInfo || shareInfo.share.disabled || loadingInfo
          }
          onClick={handleSecureDownload}
        >
          {downloading ? "Decrypting..." : "Download and decrypt"}
        </button>

        {downloadStatus ? <p className="status">{downloadStatus}</p> : null}

        <p className="muted">
          Need to manage shares? <Link to="/auth">Open owner dashboard</Link>
        </p>
      </section>
    </main>
  );
}
