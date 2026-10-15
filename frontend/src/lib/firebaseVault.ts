import { initializeApp, getApps, getApp, FirebaseOptions } from "firebase/app";
import { getFirestore, doc, getDoc, setDoc, Firestore } from "firebase/firestore";

export interface CloudVaultPayload {
  username: string;
  privateKeyB64: string;
  spkPrivateB64: string | null;
  opks: { pub: string; priv: string }[];
  contacts: string[];
  ratchets: Record<string, any>;
  exportedAt: string;
}

const RUNTIME_CONFIG_KEY = "sentinel_firebase_config";

const DEFAULT_FIREBASE_CONFIG: FirebaseOptions = {
  apiKey: "AIzaSyA8zs5VfAH6N9vn65YNH-g6-jPgKysD2L0",
  authDomain: "sentinel-desktop-app.firebaseapp.com",
  projectId: "sentinel-desktop-app",
  storageBucket: "sentinel-desktop-app.firebasestorage.app",
  messagingSenderId: "46088560162",
  appId: "1:46088560162:web:56eac7beea2d4ff081347b",
  measurementId: "G-VQHH1MPW0K",
};

export function getActiveFirebaseConfig(): FirebaseOptions | null {
  // 1. Check runtime localStorage configuration override
  if (typeof window !== "undefined") {
    try {
      const stored = localStorage.getItem(RUNTIME_CONFIG_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.apiKey && parsed.projectId) {
          return parsed;
        }
      }
    } catch {}
  }

  // 2. Check environment variables
  const envConfig: FirebaseOptions = {
    apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
    authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
    projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
    storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
  };

  if (envConfig.apiKey && envConfig.projectId) {
    return envConfig;
  }

  // 3. Fallback to user project configuration
  if (DEFAULT_FIREBASE_CONFIG.apiKey && DEFAULT_FIREBASE_CONFIG.projectId) {
    return DEFAULT_FIREBASE_CONFIG;
  }

  return null;
}

export function saveRuntimeFirebaseConfig(cfg: FirebaseOptions): boolean {
  if (typeof window === "undefined") return false;
  try {
    localStorage.setItem(RUNTIME_CONFIG_KEY, JSON.stringify(cfg));
    return true;
  } catch {
    return false;
  }
}

export function clearRuntimeFirebaseConfig(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(RUNTIME_CONFIG_KEY);
}

export function getFirebaseStatus(): {
  configured: boolean;
  source: "env" | "runtime" | "project" | "none";
  projectId?: string;
} {
  if (typeof window !== "undefined") {
    try {
      const stored = localStorage.getItem(RUNTIME_CONFIG_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.apiKey && parsed.projectId) {
          return {
            configured: true,
            source: "runtime",
            projectId: parsed.projectId,
          };
        }
      }
    } catch {}
  }

  const envHas = !!(
    process.env.NEXT_PUBLIC_FIREBASE_API_KEY &&
    process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID
  );
  if (envHas) {
    return {
      configured: true,
      source: "env",
      projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
    };
  }

  if (DEFAULT_FIREBASE_CONFIG.apiKey && DEFAULT_FIREBASE_CONFIG.projectId) {
    return {
      configured: true,
      source: "project",
      projectId: DEFAULT_FIREBASE_CONFIG.projectId,
    };
  }

  return { configured: false, source: "none" };
}

function getFirestoreDb(): Firestore | null {
  const config = getActiveFirebaseConfig();
  if (!config) return null;

  try {
    const app = getApps().length > 0 ? getApp() : initializeApp(config);
    return getFirestore(app);
  } catch (err) {
    console.warn("[Sentinel Firebase] Failed to initialize Firestore:", err);
    return null;
  }
}

// ─── Zero-Knowledge Cryptographic Derivation ──────────────────────────────

async function deriveCloudVaultKey(
  passphrase: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as unknown as ArrayBuffer,
      iterations: 600000,
      hash: "SHA-256",
    },
    passKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// ─── Cloud Vault Operations ────────────────────────────────────────────────

export async function uploadZeroKnowledgeVault(
  username: string,
  passphrase: string,
  payload: CloudVaultPayload,
): Promise<{ success: boolean; message: string }> {
  const db = getFirestoreDb();
  if (!db) {
    return {
      success: false,
      message:
        "Firebase is not configured yet. Add credentials to .env.local or run: /cloud-config <json>",
    };
  }

  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const vaultKey = await deriveCloudVaultKey(passphrase, salt);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(payload));

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      vaultKey,
      plaintext,
    );

    const vaultDoc = {
      username: username.toLowerCase(),
      salt: btoa(String.fromCharCode(...salt)),
      iv: btoa(String.fromCharCode(...iv)),
      ciphertext: btoa(
        String.fromCharCode(...new Uint8Array(ciphertext)),
      ),
      updatedAt: new Date().toISOString(),
      v: 1,
    };

    await setDoc(doc(db, "encrypted_vaults", username.toLowerCase()), vaultDoc);

    return {
      success: true,
      message: `Zero-Knowledge Cloud Vault uploaded for '${username}'. Private keys encrypted client-side with AES-256-GCM.`,
    };
  } catch (err: any) {
    return {
      success: false,
      message: `Cloud backup failed: ${err?.message || String(err)}`,
    };
  }
}

export async function downloadZeroKnowledgeVault(
  username: string,
  passphrase: string,
): Promise<{
  success: boolean;
  data?: CloudVaultPayload;
  message?: string;
}> {
  const db = getFirestoreDb();
  if (!db) {
    return {
      success: false,
      message:
        "Firebase is not configured yet. Add credentials to .env.local or run: /cloud-config <json>",
    };
  }

  try {
    const snap = await getDoc(
      doc(db, "encrypted_vaults", username.toLowerCase()),
    );
    if (!snap.exists()) {
      return {
        success: false,
        message: `No cloud vault found for '${username}'. Did you run /cloud-backup on your other device?`,
      };
    }

    const docData = snap.data();
    const salt = Uint8Array.from(atob(docData.salt), (c) => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(docData.iv), (c) => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(docData.ciphertext), (c) =>
      c.charCodeAt(0),
    );

    const vaultKey = await deriveCloudVaultKey(passphrase, salt);

    let decrypted: ArrayBuffer;
    try {
      decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        vaultKey,
        ciphertext,
      );
    } catch {
      return {
        success: false,
        message: "Incorrect passphrase. Unable to decrypt Zero-Knowledge Cloud Vault.",
      };
    }

    const payload: CloudVaultPayload = JSON.parse(
      new TextDecoder().decode(decrypted),
    );

    return {
      success: true,
      data: payload,
      message: `Successfully decrypted and restored Cloud Vault for '${username}'.`,
    };
  } catch (err: any) {
    return {
      success: false,
      message: `Cloud restore error: ${err?.message || String(err)}`,
    };
  }
}

export async function checkCloudVaultExists(username: string): Promise<boolean> {
  const db = getFirestoreDb();
  if (!db) return false;
  try {
    const snap = await getDoc(
      doc(db, "encrypted_vaults", username.toLowerCase()),
    );
    return snap.exists();
  } catch {
    return false;
  }
}
