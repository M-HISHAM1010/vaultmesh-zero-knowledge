require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const multer = require("multer");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const { MongoClient, GridFSBucket, ObjectId } = require("mongodb");

const app = express();

const NODE_ENV = process.env.NODE_ENV || "development";
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-production";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "8h";
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 12);
const MIN_PASSWORD_LENGTH = Number(process.env.MIN_PASSWORD_LENGTH || 10);
const SHARE_PASSWORD_MIN_LENGTH = Number(process.env.SHARE_PASSWORD_MIN_LENGTH || 6);
const MAX_LOGIN_ATTEMPTS = Number(process.env.MAX_LOGIN_ATTEMPTS || 5);
const LOGIN_LOCKOUT_MINUTES = Number(process.env.LOGIN_LOCKOUT_MINUTES || 15);
const ENFORCE_HTTPS = process.env.ENFORCE_HTTPS === "true";
const MAX_UPLOAD_BYTES = Number(
  process.env.MAX_UPLOAD_BYTES || 1024 * 1024 * 512,
);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 600);
const AUTH_RATE_LIMIT_MAX = Number(process.env.AUTH_RATE_LIMIT_MAX || 20);
const DOWNLOAD_RATE_LIMIT_MAX = Number(process.env.DOWNLOAD_RATE_LIMIT_MAX || 60);
const MONGODB_URI = (process.env.MONGODB_URI || "").trim();
const MONGODB_DB_NAME = process.env.MONGODB_DB_NAME || "vaultmesh";
const MONGODB_STATE_COLLECTION =
  process.env.MONGODB_STATE_COLLECTION || "vaultmesh_state";
const allowedOrigins = (process.env.CLIENT_ORIGIN || "http://localhost:5173")
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean);
const USE_ATLAS = Boolean(MONGODB_URI);

const DATA_DIR = path.join(__dirname, "data");
const STORAGE_DIR = path.join(DATA_DIR, "storage");
const TMP_DIR = path.join(DATA_DIR, "tmp");
const DB_FILE = path.join(DATA_DIR, "db.json");
const STATE_DOC_ID = "vaultmesh-main-state";

let dbLock = Promise.resolve();
let mongoClient = null;
let mongoDb = null;
let mongoStateCollection = null;
let encryptedFilesBucket = null;

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error("Origin is not allowed by CORS"));
  },
  exposedHeaders: [
    "X-File-Hash",
    "X-Encrypted-Name",
    "X-Encrypted-Name-Iv",
    "X-Encrypted-File-Iv",
    "X-Cipher-Algorithm",
    "X-Original-Mime-Type",
    "X-Original-Size",
  ],
};

const upload = multer({
  dest: TMP_DIR,
  limits: {
    fileSize: MAX_UPLOAD_BYTES,
  },
});

function getDefaultDb() {
  return {
    users: [],
    files: [],
    shares: [],
    accessLogs: [],
  };
}

function normalizeDb(raw) {
  const fallback = getDefaultDb();
  return {
    users: Array.isArray(raw.users) ? raw.users : fallback.users,
    files: Array.isArray(raw.files) ? raw.files : fallback.files,
    shares: Array.isArray(raw.shares) ? raw.shares : fallback.shares,
    accessLogs: Array.isArray(raw.accessLogs) ? raw.accessLogs : fallback.accessLogs,
  };
}

function createId(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString("hex")}`;
}

function createShareToken() {
  return crypto.randomBytes(24).toString("base64url");
}

function nowIso() {
  return new Date().toISOString();
}

function isValidEmail(email) {
  if (typeof email !== "string") {
    return false;
  }
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongPassword(password) {
  if (typeof password !== "string") {
    return false;
  }

  if (password.length < MIN_PASSWORD_LENGTH) {
    return false;
  }

  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  return hasUpper && hasLower && hasDigit && hasSpecial;
}

function isValidBase64(value) {
  if (typeof value !== "string") {
    return false;
  }

  const sanitized = value.trim();
  if (!sanitized || sanitized.length % 4 !== 0) {
    return false;
  }

  return /^[A-Za-z0-9+/]+={0,2}$/.test(sanitized);
}

function isValidSha256Hex(value) {
  if (typeof value !== "string") {
    return false;
  }
  return /^[a-f0-9]{64}$/i.test(value.trim());
}

function getLoginLockUntilIso() {
  return new Date(Date.now() + LOGIN_LOCKOUT_MINUTES * 60 * 1000).toISOString();
}

function getRemainingLockMinutes(lockUntil) {
  if (typeof lockUntil !== "string") {
    return 0;
  }

  const remainingMs = new Date(lockUntil).getTime() - Date.now();
  if (remainingMs <= 0) {
    return 0;
  }
  return Math.ceil(remainingMs / (60 * 1000));
}

function safeNumber(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return null;
  }
  return parsed;
}

function isPositiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }
  return req.socket.remoteAddress || "unknown";
}

function computeShareState(share) {
  const now = Date.now();
  const isExpired =
    typeof share.expiresAt === "string"
      ? new Date(share.expiresAt).getTime() <= now
      : false;
  const reachedMaxDownloads =
    Number.isInteger(share.maxDownloads) && share.downloadCount >= share.maxDownloads;
  const oneTimeConsumed = Boolean(share.oneTime) && share.downloadCount >= 1;
  return {
    isExpired,
    reachedMaxDownloads,
    oneTimeConsumed,
    isDisabled: Boolean(share.revoked) || isExpired || reachedMaxDownloads || oneTimeConsumed,
  };
}

function sanitizeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
  };
}

function sanitizeShareForOwner(share) {
  return {
    token: share.token,
    createdAt: share.createdAt,
    expiresAt: share.expiresAt,
    maxDownloads: share.maxDownloads,
    downloadCount: share.downloadCount,
    oneTime: share.oneTime,
    revoked: share.revoked,
    passwordProtected: Boolean(share.passwordHash),
  };
}

function sanitizeFileForOwner(file, shares) {
  return {
    id: file.id,
    ownerId: file.ownerId,
    size: file.size,
    originalSize: file.originalSize,
    mimeType: file.mimeType,
    cipherAlgorithm: file.cipherAlgorithm,
    encryptedName: file.encryptedName,
    encryptedNameIv: file.encryptedNameIv,
    encryptedFileIv: file.encryptedFileIv,
    fileHash: file.fileHash,
    createdAt: file.createdAt,
    shares: shares.map(sanitizeShareForOwner),
  };
}

function createJwt(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      name: user.name,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN },
  );
}

function createRequestId() {
  if (typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return createId("req");
}

function createLimiter({ max, message }) {
  return rateLimit({
    windowMs: RATE_LIMIT_WINDOW_MS,
    max,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json({ message });
    },
  });
}

async function pathExists(filePath) {
  try {
    await fsp.access(filePath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function ensureLocalPersistence() {
  await fsp.mkdir(STORAGE_DIR, { recursive: true });
  const hasDb = await pathExists(DB_FILE);
  if (!hasDb) {
    await fsp.writeFile(DB_FILE, JSON.stringify(getDefaultDb(), null, 2), "utf8");
  }
}

async function ensureAtlasPersistence() {
  if (mongoClient) {
    return;
  }

  mongoClient = new MongoClient(MONGODB_URI, {
    maxPoolSize: 10,
  });
  await mongoClient.connect();
  mongoDb = mongoClient.db(MONGODB_DB_NAME);
  mongoStateCollection = mongoDb.collection(MONGODB_STATE_COLLECTION);
  encryptedFilesBucket = new GridFSBucket(mongoDb, {
    bucketName: "encrypted_files",
  });

  await mongoStateCollection.updateOne(
    { _id: STATE_DOC_ID },
    {
      $setOnInsert: {
        _id: STATE_DOC_ID,
        ...getDefaultDb(),
        createdAt: nowIso(),
      },
    },
    { upsert: true },
  );
}

async function ensurePersistence() {
  await fsp.mkdir(TMP_DIR, { recursive: true });
  if (USE_ATLAS) {
    await ensureAtlasPersistence();
    return;
  }
  await ensureLocalPersistence();
}

async function readLocalDb() {
  const raw = await fsp.readFile(DB_FILE, "utf8");
  try {
    const parsed = JSON.parse(raw);
    return normalizeDb(parsed);
  } catch {
    return getDefaultDb();
  }
}

async function writeLocalDb(db) {
  const tempPath = `${DB_FILE}.tmp`;
  await fsp.writeFile(tempPath, JSON.stringify(db, null, 2), "utf8");
  await fsp.rename(tempPath, DB_FILE);
}

async function readAtlasDb() {
  const rawState = await mongoStateCollection.findOne({ _id: STATE_DOC_ID });
  if (!rawState) {
    return getDefaultDb();
  }
  const { _id, createdAt, updatedAt, ...state } = rawState;
  return normalizeDb(state);
}

async function writeAtlasDb(db) {
  const state = normalizeDb(db);
  await mongoStateCollection.replaceOne(
    { _id: STATE_DOC_ID },
    {
      _id: STATE_DOC_ID,
      ...state,
      updatedAt: nowIso(),
    },
    { upsert: true },
  );
}

async function readDb() {
  await ensurePersistence();
  if (USE_ATLAS) {
    return readAtlasDb();
  }
  return readLocalDb();
}

async function writeDb(db) {
  await ensurePersistence();
  if (USE_ATLAS) {
    await writeAtlasDb(db);
    return;
  }
  await writeLocalDb(db);
}

async function withDbLock(task) {
  const previous = dbLock;
  let release;
  dbLock = new Promise((resolve) => {
    release = resolve;
  });

  await previous;

  try {
    return await task();
  } finally {
    release();
  }
}

async function safeUnlink(filePath) {
  if (!filePath) {
    return;
  }
  try {
    await fsp.unlink(filePath);
  } catch {
    // Ignore cleanup errors.
  }
}

async function storeEncryptedPayloadInAtlas(fileId, tempFilePath) {
  if (!encryptedFilesBucket) {
    throw new Error("Atlas storage is not initialized.");
  }

  const gridFsFileId = await new Promise((resolve, reject) => {
    const uploadStream = encryptedFilesBucket.openUploadStream(`${fileId}.bin`, {
      metadata: {
        fileId,
        uploadedAt: nowIso(),
      },
    });
    const readStream = fs.createReadStream(tempFilePath);

    readStream.on("error", reject);
    uploadStream.on("error", reject);
    uploadStream.on("finish", () => {
      resolve(uploadStream.id.toString());
    });

    readStream.pipe(uploadStream);
  });

  await safeUnlink(tempFilePath);
  return {
    storedName: null,
    gridFsFileId,
  };
}

async function storeEncryptedPayloadLocally(fileId, tempFilePath) {
  const storedName = `${fileId}.bin`;
  const targetPath = path.join(STORAGE_DIR, storedName);
  await fsp.rename(tempFilePath, targetPath);
  return {
    storedName,
    gridFsFileId: null,
  };
}

async function storeEncryptedPayload(fileId, tempFilePath) {
  if (USE_ATLAS) {
    return storeEncryptedPayloadInAtlas(fileId, tempFilePath);
  }
  return storeEncryptedPayloadLocally(fileId, tempFilePath);
}

function createDownloadStreamFromRecord(fileRecord) {
  if (USE_ATLAS) {
    if (!fileRecord.gridFsFileId || !encryptedFilesBucket) {
      return null;
    }

    try {
      const bucketFileId = new ObjectId(fileRecord.gridFsFileId);
      return encryptedFilesBucket.openDownloadStream(bucketFileId);
    } catch {
      return null;
    }
  }

  if (!fileRecord.storedName) {
    return null;
  }

  const filePath = path.join(STORAGE_DIR, fileRecord.storedName);
  return fs.createReadStream(filePath);
}

function addAccessLog(db, payload) {
  db.accessLogs.push({
    id: createId("log"),
    createdAt: nowIso(),
    ...payload,
  });
}

function authRequired(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    res.status(401).json({ message: "Missing bearer token." });
    return;
  }

  const token = authHeader.slice(7);

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = {
      id: payload.sub,
      email: payload.email,
      name: payload.name,
    };
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired token." });
  }
}

const globalRateLimiter = createLimiter({
  max: RATE_LIMIT_MAX,
  message: "Too many requests. Please try again shortly.",
});

const authRateLimiter = createLimiter({
  max: AUTH_RATE_LIMIT_MAX,
  message: "Too many authentication attempts. Please wait and retry.",
});

const downloadRateLimiter = createLimiter({
  max: DOWNLOAD_RATE_LIMIT_MAX,
  message: "Too many download attempts from this client. Try again later.",
});

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors(corsOptions));
app.use(express.json({ limit: "2mb" }));
app.use(morgan("tiny"));
app.use((req, res, next) => {
  if (!ENFORCE_HTTPS) {
    next();
    return;
  }

  const forwardedProto = String(req.headers["x-forwarded-proto"] || "")
    .split(",")[0]
    .trim()
    .toLowerCase();

  if (req.secure || forwardedProto === "https") {
    next();
    return;
  }

  res.status(400).json({ message: "HTTPS is required." });
});
app.use((req, res, next) => {
  const requestId = createRequestId();
  req.requestId = requestId;
  res.setHeader("X-Request-Id", requestId);
  next();
});
app.use("/api", (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});
app.use("/api", globalRateLimiter);

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "zero-knowledge-file-share-api",
    storageMode: USE_ATLAS ? "atlas" : "local",
    time: nowIso(),
  });
});

app.post("/api/auth/register", authRateLimiter, async (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  if (!name || name.length < 2) {
    res.status(400).json({ message: "Name must contain at least 2 characters." });
    return;
  }

  if (!isValidEmail(email)) {
    res.status(400).json({ message: "A valid email address is required." });
    return;
  }

  if (!isStrongPassword(password)) {
    res.status(400).json({
      message:
        `Password must be at least ${MIN_PASSWORD_LENGTH} characters and include uppercase, lowercase, number, and symbol.`,
    });
    return;
  }

  const result = await withDbLock(async () => {
    const db = await readDb();
    const alreadyExists = db.users.some((user) => user.email === email);
    if (alreadyExists) {
      return { status: 409, body: { message: "An account with this email already exists." } };
    }

    const user = {
      id: createId("usr"),
      name,
      email,
      passwordHash: await bcrypt.hash(password, BCRYPT_ROUNDS),
      failedLoginCount: 0,
      lockUntil: null,
      createdAt: nowIso(),
    };

    db.users.push(user);
    await writeDb(db);

    return {
      status: 201,
      body: {
        token: createJwt(user),
        user: sanitizeUser(user),
      },
    };
  });

  res.status(result.status).json(result.body);
});

app.post("/api/auth/login", authRateLimiter, async (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  if (!isValidEmail(email) || !password) {
    res.status(400).json({ message: "Email and password are required." });
    return;
  }

  const result = await withDbLock(async () => {
    const db = await readDb();
    const user = db.users.find((entry) => entry.email === email);
    if (!user) {
      return {
        status: 401,
        body: { message: "Invalid login credentials." },
      };
    }

    const now = Date.now();
    const lockUntilMs = user.lockUntil ? new Date(user.lockUntil).getTime() : 0;
    if (lockUntilMs && lockUntilMs > now) {
      return {
        status: 423,
        body: {
          message: `Account temporarily locked. Try again in ${getRemainingLockMinutes(
            user.lockUntil,
          )} minute(s).`,
        },
      };
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      user.failedLoginCount = Number.isInteger(user.failedLoginCount)
        ? user.failedLoginCount + 1
        : 1;

      if (user.failedLoginCount >= MAX_LOGIN_ATTEMPTS) {
        user.lockUntil = getLoginLockUntilIso();
        user.failedLoginCount = 0;
      }

      await writeDb(db);

      return {
        status: 401,
        body: { message: "Invalid login credentials." },
      };
    }

    user.failedLoginCount = 0;
    user.lockUntil = null;
    await writeDb(db);

    return {
      status: 200,
      body: {
        token: createJwt(user),
        user: sanitizeUser(user),
      },
    };
  });

  res.status(result.status).json(result.body);
});

app.get("/api/files", authRequired, async (req, res) => {
  const db = await readDb();
  const ownedFiles = db.files
    .filter((file) => file.ownerId === req.user.id)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

  const sharesByFile = new Map();
  for (const share of db.shares) {
    if (share.ownerId !== req.user.id) {
      continue;
    }
    if (!sharesByFile.has(share.fileId)) {
      sharesByFile.set(share.fileId, []);
    }
    sharesByFile.get(share.fileId).push(share);
  }

  const files = ownedFiles.map((file) => {
    const shares = sharesByFile.get(file.id) || [];
    shares.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return sanitizeFileForOwner(file, shares);
  });

  res.json({ files });
});

app.post("/api/files/upload", authRequired, upload.single("encryptedFile"), async (req, res) => {
  try {
    if (!req.file) {
      res.status(400).json({ message: "Encrypted file payload is required." });
      return;
    }

    const encryptedName =
      typeof req.body?.encryptedName === "string" ? req.body.encryptedName.trim() : "";
    const encryptedNameIv =
      typeof req.body?.encryptedNameIv === "string" ? req.body.encryptedNameIv.trim() : "";
    const encryptedFileIv =
      typeof req.body?.encryptedFileIv === "string" ? req.body.encryptedFileIv.trim() : "";
    const fileHash =
      typeof req.body?.fileHash === "string" ? req.body.fileHash.trim().toLowerCase() : "";
    const cipherAlgorithm =
      typeof req.body?.cipherAlgorithm === "string" ? req.body.cipherAlgorithm : "AES-GCM";
    const mimeType =
      typeof req.body?.mimeType === "string" && req.body.mimeType.trim().length > 0
        ? req.body.mimeType
        : "application/octet-stream";
    const originalSize = safeNumber(req.body?.originalSize);

    if (!encryptedName || !encryptedNameIv || !encryptedFileIv || !fileHash) {
      await safeUnlink(req.file.path);
      res.status(400).json({
        message:
          "Missing encrypted metadata. Provide encryptedName, encryptedNameIv, encryptedFileIv, and fileHash.",
      });
      return;
    }

    if (
      !isValidBase64(encryptedName) ||
      !isValidBase64(encryptedNameIv) ||
      !isValidBase64(encryptedFileIv)
    ) {
      await safeUnlink(req.file.path);
      res.status(400).json({ message: "Encrypted metadata contains invalid base64 values." });
      return;
    }

    if (!isValidSha256Hex(fileHash)) {
      await safeUnlink(req.file.path);
      res.status(400).json({ message: "fileHash must be a valid SHA-256 hex string." });
      return;
    }

    if (encryptedName.length > 4096 || encryptedNameIv.length > 128 || encryptedFileIv.length > 128) {
      await safeUnlink(req.file.path);
      res.status(400).json({ message: "Encrypted metadata exceeds allowed length." });
      return;
    }

    if (originalSize !== null && (!isPositiveInteger(originalSize) || originalSize > MAX_UPLOAD_BYTES)) {
      await safeUnlink(req.file.path);
      res
        .status(400)
        .json({ message: "originalSize must be a positive integer within upload size limits." });
      return;
    }

    const fileId = createId("fil");
    const storageRef = await storeEncryptedPayload(fileId, req.file.path);

    const result = await withDbLock(async () => {
      const db = await readDb();
      const fileRecord = {
        id: fileId,
        ownerId: req.user.id,
        storedName: storageRef.storedName,
        gridFsFileId: storageRef.gridFsFileId,
        encryptedName,
        encryptedNameIv,
        encryptedFileIv,
        fileHash,
        cipherAlgorithm,
        size: req.file.size,
        originalSize: isPositiveInteger(originalSize) ? originalSize : null,
        mimeType,
        createdAt: nowIso(),
      };

      db.files.push(fileRecord);
      await writeDb(db);

      return sanitizeFileForOwner(fileRecord, []);
    });

    res.status(201).json({ file: result });
  } catch (error) {
    await safeUnlink(req.file?.path);
    res.status(500).json({ message: "Unable to store encrypted file." });
  }
});

app.post("/api/files/:fileId/shares", authRequired, async (req, res) => {
  const fileId = req.params.fileId;
  const rawExpiresInHours = req.body?.expiresInHours;
  const rawMaxDownloads = req.body?.maxDownloads;
  const oneTime = Boolean(req.body?.oneTime);
  const password = typeof req.body?.password === "string" ? req.body.password.trim() : "";

  if (password && password.length < SHARE_PASSWORD_MIN_LENGTH) {
    res.status(400).json({
      message: `Share password must be at least ${SHARE_PASSWORD_MIN_LENGTH} characters long.`,
    });
    return;
  }

  let expiresAt = null;
  if (rawExpiresInHours !== undefined && rawExpiresInHours !== null && rawExpiresInHours !== "") {
    const hours = safeNumber(rawExpiresInHours);
    if (!hours || hours <= 0 || hours > 24 * 365) {
      res.status(400).json({ message: "expiresInHours must be between 1 and 8760." });
      return;
    }
    expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
  }

  let maxDownloads = null;
  if (rawMaxDownloads !== undefined && rawMaxDownloads !== null && rawMaxDownloads !== "") {
    const downloads = safeNumber(rawMaxDownloads);
    if (!isPositiveInteger(downloads)) {
      res.status(400).json({ message: "maxDownloads must be a positive integer." });
      return;
    }
    maxDownloads = downloads;
  }

  const result = await withDbLock(async () => {
    const db = await readDb();
    const file = db.files.find((entry) => entry.id === fileId && entry.ownerId === req.user.id);

    if (!file) {
      return { status: 404, body: { message: "File not found." } };
    }

    const share = {
      id: createId("shr"),
      token: createShareToken(),
      fileId: file.id,
      ownerId: req.user.id,
      createdAt: nowIso(),
      expiresAt,
      maxDownloads,
      downloadCount: 0,
      oneTime,
      revoked: false,
      passwordHash: password ? await bcrypt.hash(password, BCRYPT_ROUNDS) : null,
    };

    db.shares.push(share);
    await writeDb(db);

    return {
      status: 201,
      body: {
        share: sanitizeShareForOwner(share),
        publicPath: `/share/${share.token}`,
      },
    };
  });

  res.status(result.status).json(result.body);
});

app.post("/api/shares/:token/revoke", authRequired, async (req, res) => {
  const token = req.params.token;

  const result = await withDbLock(async () => {
    const db = await readDb();
    const share = db.shares.find((entry) => entry.token === token);

    if (!share) {
      return { status: 404, body: { message: "Share link not found." } };
    }

    if (share.ownerId !== req.user.id) {
      return { status: 403, body: { message: "You do not own this share link." } };
    }

    share.revoked = true;
    await writeDb(db);

    return { status: 200, body: { share: sanitizeShareForOwner(share) } };
  });

  res.status(result.status).json(result.body);
});

app.get("/api/files/:fileId/logs", authRequired, async (req, res) => {
  const fileId = req.params.fileId;
  const db = await readDb();

  const file = db.files.find((entry) => entry.id === fileId && entry.ownerId === req.user.id);
  if (!file) {
    res.status(404).json({ message: "File not found." });
    return;
  }

  const shareTokens = new Set(
    db.shares.filter((share) => share.fileId === fileId).map((share) => share.token),
  );

  const logs = db.accessLogs
    .filter((entry) => shareTokens.has(entry.shareToken))
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .slice(0, 100);

  res.json({ logs });
});

app.get("/api/shares/:token/info", async (req, res) => {
  const token = req.params.token;
  const db = await readDb();

  const share = db.shares.find((entry) => entry.token === token);
  if (!share) {
    res.status(404).json({ message: "Share link not found." });
    return;
  }

  const file = db.files.find((entry) => entry.id === share.fileId);
  if (!file) {
    res.status(404).json({ message: "File not available." });
    return;
  }

  const state = computeShareState(share);

  res.json({
    share: {
      token: share.token,
      requiresPassword: Boolean(share.passwordHash),
      createdAt: share.createdAt,
      expiresAt: share.expiresAt,
      maxDownloads: share.maxDownloads,
      downloadCount: share.downloadCount,
      oneTime: share.oneTime,
      revoked: share.revoked,
      isExpired: state.isExpired,
      limitReached: state.reachedMaxDownloads || state.oneTimeConsumed,
      disabled: state.isDisabled,
    },
    file: {
      id: file.id,
      size: file.size,
      originalSize: file.originalSize,
      mimeType: file.mimeType,
      cipherAlgorithm: file.cipherAlgorithm,
    },
  });
});

app.post("/api/shares/:token/download", downloadRateLimiter, async (req, res) => {
  const token = req.params.token;
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  const result = await withDbLock(async () => {
    const db = await readDb();
    const share = db.shares.find((entry) => entry.token === token);

    if (!share) {
      return { status: 404, body: { message: "Share link not found." } };
    }

    const file = db.files.find((entry) => entry.id === share.fileId);
    if (!file) {
      addAccessLog(db, {
        shareToken: token,
        fileId: share.fileId,
        status: "denied",
        reason: "missing_file",
        ip: getClientIp(req),
        userAgent: req.headers["user-agent"] || "unknown",
      });
      await writeDb(db);
      return { status: 404, body: { message: "File is no longer available." } };
    }

    const state = computeShareState(share);
    if (share.revoked) {
      addAccessLog(db, {
        shareToken: token,
        fileId: file.id,
        status: "denied",
        reason: "revoked",
        ip: getClientIp(req),
        userAgent: req.headers["user-agent"] || "unknown",
      });
      await writeDb(db);
      return { status: 403, body: { message: "This share link has been revoked." } };
    }

    if (state.isExpired) {
      addAccessLog(db, {
        shareToken: token,
        fileId: file.id,
        status: "denied",
        reason: "expired",
        ip: getClientIp(req),
        userAgent: req.headers["user-agent"] || "unknown",
      });
      await writeDb(db);
      return { status: 410, body: { message: "This share link has expired." } };
    }

    if (state.reachedMaxDownloads || state.oneTimeConsumed) {
      addAccessLog(db, {
        shareToken: token,
        fileId: file.id,
        status: "denied",
        reason: "download_limit_reached",
        ip: getClientIp(req),
        userAgent: req.headers["user-agent"] || "unknown",
      });
      await writeDb(db);
      return { status: 410, body: { message: "Download limit has been reached." } };
    }

    if (share.passwordHash) {
      const validPassword = await bcrypt.compare(password, share.passwordHash);
      if (!validPassword) {
        addAccessLog(db, {
          shareToken: token,
          fileId: file.id,
          status: "denied",
          reason: "invalid_password",
          ip: getClientIp(req),
          userAgent: req.headers["user-agent"] || "unknown",
        });
        await writeDb(db);
        return { status: 401, body: { message: "Invalid share password." } };
      }
    }

    share.downloadCount += 1;
    addAccessLog(db, {
      shareToken: token,
      fileId: file.id,
      status: "granted",
      reason: "ok",
      ip: getClientIp(req),
      userAgent: req.headers["user-agent"] || "unknown",
    });

    await writeDb(db);
    return {
      status: 200,
      file,
    };
  });

  if (result.status !== 200) {
    res.status(result.status).json(result.body);
    return;
  }

  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Length", String(result.file.size));
  res.setHeader("Content-Disposition", `attachment; filename="${result.file.id}.enc"`);
  res.setHeader("X-File-Hash", result.file.fileHash);
  res.setHeader("X-Encrypted-Name", result.file.encryptedName);
  res.setHeader("X-Encrypted-Name-Iv", result.file.encryptedNameIv);
  res.setHeader("X-Encrypted-File-Iv", result.file.encryptedFileIv);
  res.setHeader("X-Cipher-Algorithm", result.file.cipherAlgorithm);
  res.setHeader("X-Original-Mime-Type", result.file.mimeType || "application/octet-stream");
  if (result.file.originalSize) {
    res.setHeader("X-Original-Size", String(result.file.originalSize));
  }

  const stream = createDownloadStreamFromRecord(result.file);
  if (!stream) {
    res.status(500).json({ message: "Encrypted data file is missing on server storage." });
    return;
  }

  stream.on("error", (error) => {
    if (!res.headersSent) {
      const isNotFound =
        String(error?.message || "").toLowerCase().includes("not found") ||
        error?.code === "ENOENT";

      res
        .status(isNotFound ? 404 : 500)
        .json({ message: isNotFound ? "Encrypted file content is missing." : "Failed to stream encrypted file." });
      return;
    }
    res.end();
  });
  stream.pipe(res);
});

app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
    res.status(413).json({ message: "Encrypted upload exceeds MAX_UPLOAD_BYTES." });
    return;
  }

  if (error?.message === "Origin is not allowed by CORS") {
    res.status(403).json({ message: "Origin is not allowed by CORS policy." });
    return;
  }

  res.status(500).json({ message: "Unexpected server error." });
});

async function start() {
  await ensurePersistence();
  app.listen(PORT, () => {
    console.log(`Zero-knowledge API listening on http://localhost:${PORT}`);
    console.log(
      `Storage mode: ${USE_ATLAS ? `atlas (${MONGODB_DB_NAME})` : "local-json"}`,
    );
    console.log(`HTTPS enforcement: ${ENFORCE_HTTPS ? "enabled" : "disabled"}`);
    console.log(`Allowed origins: ${allowedOrigins.join(", ")}`);

    if (NODE_ENV === "production" && JWT_SECRET === "change-me-in-production") {
      console.warn("Security warning: JWT_SECRET is using default value in production.");
    }
  });
}

start().catch((error) => {
  console.error("Unable to start server", error);
  process.exit(1);
});
