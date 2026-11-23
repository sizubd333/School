import express from "express";
import type { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;
const HOST = "0.0.0.0";

const ALL_MODULES = [
  "dashboard",
  "students",
  "teachers",
  "classes",
  "attendance",
  "results",
  "fees",
  "notices",
  "routine",
  "library",
  "transport",
  "admissions",
  "employees",
  "departments",
  "office-attendance",
  "leaves",
  "payroll",
  "tasks",
  "expenses",
  "student-costs",
  "office-docs",
  "settings",
];

const STAFF_MODULES = [
  "dashboard",
  "students",
  "teachers",
  "classes",
  "attendance",
  "results",
  "notices",
  "routine",
  "library",
  "transport",
];

const STUDENT_MODULES = [
  "dashboard",
  "notices",
  "routine",
  "results",
  "library",
  "transport",
];

const MASTER_ADMIN_EMAIL = (
  process.env.MASTER_ADMIN_EMAIL || "sizu111@gmail.com"
)
  .trim()
  .toLowerCase();

const AUTH_DATA_DIR = path.resolve(__dirname, ".data");
const AUTH_STORE_FILE = path.join(AUTH_DATA_DIR, "master-auth.json");

interface ClaimedMaster {
  email: string;
  salt: string;
  hash: string;
}

interface PersistedAuthStore {
  email?: string;
  salt?: string;
  hash?: string;
  sessionSecret?: string;
  updatedAt?: string;
}

function readAuthStore(): PersistedAuthStore {
  try {
    if (!fs.existsSync(AUTH_STORE_FILE)) return {};
    const raw = fs.readFileSync(AUTH_STORE_FILE, "utf8");
    const parsed = JSON.parse(raw) as PersistedAuthStore;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeAuthStore(store: PersistedAuthStore): void {
  fs.mkdirSync(AUTH_DATA_DIR, { recursive: true });
  fs.writeFileSync(AUTH_STORE_FILE, JSON.stringify(store, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
}

const initialStore = readAuthStore();
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  (typeof initialStore.sessionSecret === "string" && initialStore.sessionSecret.length >= 32
    ? initialStore.sessionSecret
    : crypto.randomBytes(32).toString("hex"));
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

interface AuthUser {
  id: string;
  role: "master" | "admin" | "student";
  year?: string;
  isSuper: boolean;
  isMasterAdmin: boolean;
  allowedModules: string[];
  via: string;
}

interface TokenPayload extends AuthUser {
  jti: string;
  exp: number;
}

interface AuthedRequest extends Request {
  authUser?: TokenPayload;
}

let claimedMaster: ClaimedMaster | null =
  typeof initialStore.email === "string" &&
  initialStore.email.trim().toLowerCase() === MASTER_ADMIN_EMAIL &&
  typeof initialStore.salt === "string" &&
  typeof initialStore.hash === "string" &&
  initialStore.salt &&
  initialStore.hash
    ? {
        email: MASTER_ADMIN_EMAIL,
        salt: initialStore.salt,
        hash: initialStore.hash,
      }
    : null;
const revokedTokens = new Set<string>();

function getEnvMasterPassword(): string {
  return (process.env.MASTER_ADMIN_PASSWORD || "").trim();
}

function hashPassword(password: string): { salt: string; hash: string } {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function verifyScryptPassword(
  password: string,
  salt: string,
  expectedHashHex: string
): boolean {
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHashHex, "hex");
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

function verifyConstantTimeString(candidate: string, expected: string): boolean {
  const a = crypto.createHash("sha256").update(candidate, "utf8").digest();
  const b = crypto.createHash("sha256").update(expected, "utf8").digest();
  return crypto.timingSafeEqual(a, b);
}

function signToken(user: AuthUser): string {
  const payload: TokenPayload = {
    ...user,
    jti: crypto.randomUUID(),
    exp: Date.now() + TOKEN_TTL_MS,
  };
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url"
  );
  const sig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(encoded)
    .digest("base64url");
  return `${encoded}.${sig}`;
}

function verifyToken(token: string): TokenPayload | null {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  if (!encoded || !sig) return null;

  const expectedSig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(encoded)
    .digest("base64url");

  const sigBuf = Buffer.from(sig, "utf8");
  const expectedBuf = Buffer.from(expectedSig, "utf8");
  if (sigBuf.length !== expectedBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return null;

  try {
    const parsed = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    ) as TokenPayload;
    if (!parsed || typeof parsed.exp !== "number" || Date.now() > parsed.exp) {
      return null;
    }
    if (!parsed.jti || revokedTokens.has(parsed.jti)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function extractBearerToken(req: Request): string {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return "";
  return header.slice(7).trim();
}

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = extractBearerToken(req);
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({
      error: "UNAUTHORIZED",
      message: "অনুগ্রহ করে পুনরায় লগইন করুন।",
    });
  }
  req.authUser = payload;
  next();
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: "256kb" }));

  app.get("/api/auth/status", (req: Request, res: Response) => {
    const envPw = getEnvMasterPassword();
    const masterConfigured = Boolean(envPw || claimedMaster);
    const needsMasterSetup = !masterConfigured;
    const token = extractBearerToken(req);
    const user = token ? verifyToken(token) : null;

    res.json({
      masterAdminEmail: MASTER_ADMIN_EMAIL,
      masterConfigured,
      needsMasterSetup,
      authenticated: Boolean(user),
      user: user
        ? {
            id: user.id,
            role: user.role,
            year: user.year,
            isSuper: user.isSuper,
            isMasterAdmin: user.isMasterAdmin,
            allowedModules: user.allowedModules,
            via: user.via,
          }
        : null,
    });
  });

  app.post("/api/auth/setup-master", (req: Request, res: Response) => {
    const envPw = getEnvMasterPassword();
    if (envPw || claimedMaster) {
      return res.status(409).json({
        error: "ALREADY_CONFIGURED",
        message: "মাস্টার অ্যাডমিন পাসওয়ার্ড ইতিমধ্যেই সেট করা আছে।",
      });
    }

    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";

    if (email !== MASTER_ADMIN_EMAIL) {
      return res.status(400).json({
        error: "INVALID_MASTER_ID",
        message: `মাস্টার অ্যাডমিন আইডি অবশ্যই ${MASTER_ADMIN_EMAIL} হতে হবে।`,
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "WEAK_PASSWORD",
        message: "পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে।",
      });
    }

    const { salt, hash } = hashPassword(password);
    claimedMaster = { email: MASTER_ADMIN_EMAIL, salt, hash };
    try {
      writeAuthStore({
        email: MASTER_ADMIN_EMAIL,
        salt,
        hash,
        sessionSecret: SESSION_SECRET,
        updatedAt: new Date().toISOString(),
      });
    } catch (err) {
      console.error("Failed to persist master auth store:", err);
      return res.status(500).json({
        error: "PERSISTENCE_ERROR",
        message: "পাসওয়ার্ড সংরক্ষণ করা যায়নি। আবার চেষ্টা করুন।",
      });
    }

    const user: AuthUser = {
      id: MASTER_ADMIN_EMAIL,
      role: "master",
      isSuper: true,
      isMasterAdmin: true,
      allowedModules: ALL_MODULES,
      via: "master",
    };

    const token = signToken(user);
    return res.json({ token, user });
  });

  app.post("/api/auth/login", (req: Request, res: Response) => {
    const rawRole = typeof req.body?.role === "string" ? req.body.role.trim() : "";
    const rawId = typeof req.body?.id === "string" ? req.body.id.trim() : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    const year = typeof req.body?.year === "string" ? req.body.year.trim() : "২০২৬";

    if (!rawId || !password) {
      return res.status(400).json({
        error: "MISSING_FIELDS",
        message: "ইউজার আইডি ও পাসওয়ার্ড উভয়ই দিন।",
      });
    }

    const normalizedId = rawId.toLowerCase();
    const isMasterAttempt = rawRole === "master" || normalizedId === MASTER_ADMIN_EMAIL;

    if (isMasterAttempt) {
      if (normalizedId !== MASTER_ADMIN_EMAIL) {
        return res.status(401).json({
          error: "INVALID_CREDENTIALS",
          message: "মাস্টার অ্যাডমিন আইডি বা পাসওয়ার্ড সঠিক নয়।",
        });
      }

      const envPw = getEnvMasterPassword();
      if (!envPw && !claimedMaster) {
        return res.status(409).json({
          error: "MASTER_SETUP_REQUIRED",
          needsMasterSetup: true,
          message: "প্রথমে মাস্টার অ্যাডমিন পাসওয়ার্ড সেটআপ করুন।",
        });
      }

      const isValid = envPw
        ? verifyConstantTimeString(password, envPw)
        : verifyScryptPassword(
            password,
            claimedMaster!.salt,
            claimedMaster!.hash
          );

      if (!isValid) {
        return res.status(401).json({
          error: "INVALID_CREDENTIALS",
          message: "মাস্টার অ্যাডমিন আইডি বা পাসওয়ার্ড সঠিক নয়।",
        });
      }

      const user: AuthUser = {
        id: MASTER_ADMIN_EMAIL,
        role: "master",
        isSuper: true,
        isMasterAdmin: true,
        allowedModules: ALL_MODULES,
        via: "master",
      };
      const token = signToken(user);
      return res.json({ token, user });
    }

    if (rawRole === "admin") {
      const user: AuthUser = {
        id: rawId,
        role: "admin",
        isSuper: false,
        isMasterAdmin: false,
        allowedModules: STAFF_MODULES,
        via: "demo",
      };
      const token = signToken(user);
      return res.json({ token, user });
    }

    if (rawRole === "student") {
      const user: AuthUser = {
        id: rawId,
        role: "student",
        year,
        isSuper: false,
        isMasterAdmin: false,
        allowedModules: STUDENT_MODULES,
        via: "demo",
      };
      const token = signToken(user);
      return res.json({ token, user });
    }

    return res.status(400).json({
      error: "INVALID_ROLE",
      message: "অবৈধ ভূমিকা নির্বাচন করা হয়েছে।",
    });
  });

  app.get("/api/auth/me", requireAuth, (req: AuthedRequest, res: Response) => {
    const u = req.authUser!;
    res.json({
      user: {
        id: u.id,
        role: u.role,
        year: u.year,
        isSuper: u.isSuper,
        isMasterAdmin: u.isMasterAdmin,
        allowedModules: u.allowedModules,
        via: u.via,
      },
    });
  });

  app.post("/api/auth/logout", (req: Request, res: Response) => {
    const token = extractBearerToken(req);
    const payload = token ? verifyToken(token) : null;
    if (payload?.jti) {
      revokedTokens.add(payload.jti);
    }
    res.json({ ok: true });
  });

  app.get("/api/console/access", requireAuth, (req: AuthedRequest, res: Response) => {
    const u = req.authUser!;
    res.json({
      isMasterAdmin: u.isMasterAdmin,
      allowedModules: u.allowedModules,
    });
  });

  if (process.env.NODE_ENV !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, "dist");
    app.use(express.static(distDir));
    app.get("*", (req: Request, res: Response, next: NextFunction) => {
      if (req.path.startsWith("/api/")) return next();
      const indexFile = path.join(distDir, "index.html");
      if (fs.existsSync(indexFile)) {
        return res.sendFile(indexFile);
      }
      return res.status(404).send("Not found");
    });
  }

  app.listen(PORT, HOST, () => {
    console.log(`Server listening on http://${HOST}:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
