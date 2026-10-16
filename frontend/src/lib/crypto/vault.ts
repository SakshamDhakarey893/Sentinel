export const CANARY_PAYLOAD = "SENTINEL_VAULT_V1_OK";

export function zeroizeBuffer(buf: ArrayBuffer | Uint8Array | null | undefined) {
  if (!buf) return;
  try {
    const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    crypto.getRandomValues(view);
    view.fill(0);
  } catch {}
}

export async function deriveVaultKey(
  passphrase: string,
  saltBytes: Uint8Array,
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes as unknown as BufferSource,
      iterations: 100_000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptWithVaultKey(
  vaultKey: CryptoKey,
  plaintext: string,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    vaultKey,
    encoded,
  );
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
}

export async function decryptWithVaultKey(
  vaultKey: CryptoKey,
  b64: string,
): Promise<string> {
  const combined = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const data = combined.slice(12);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    vaultKey,
    data,
  );
  return new TextDecoder().decode(decrypted);
}

export function hasVaultConfigured(username: string): boolean {
  return !!(
    localStorage.getItem(`sentinel_salt_${username}`) &&
    localStorage.getItem(`sentinel_canary_${username}`)
  );
}

export async function setupNewVault(
  username: string,
  passphrase: string,
): Promise<CryptoKey> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = btoa(String.fromCharCode(...salt));
  localStorage.setItem(`sentinel_salt_${username}`, saltB64);

  const vaultKey = await deriveVaultKey(passphrase, salt);
  const canaryEnc = await encryptWithVaultKey(vaultKey, CANARY_PAYLOAD);
  localStorage.setItem(`sentinel_canary_${username}`, canaryEnc);
  return vaultKey;
}

export async function unlockVault(
  username: string,
  passphrase: string,
): Promise<CryptoKey | null> {
  const saltB64 = localStorage.getItem(`sentinel_salt_${username}`);
  const canaryEnc = localStorage.getItem(`sentinel_canary_${username}`);
  if (!saltB64 || !canaryEnc) {
    return null;
  }
  try {
    const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
    const vaultKey = await deriveVaultKey(passphrase, salt);
    const decryptedCanary = await decryptWithVaultKey(vaultKey, canaryEnc);
    if (decryptedCanary === CANARY_PAYLOAD) {
      return vaultKey;
    }
    return null;
  } catch {
    return null;
  }
}

export async function savePrivateKey(
  username: string,
  b64: string,
  vaultKey?: CryptoKey | null,
) {
  if (vaultKey) {
    const enc = await encryptWithVaultKey(vaultKey, b64);
    localStorage.setItem(
      `sentinel_priv_${username}`,
      JSON.stringify({ v: 2, enc }),
    );
  } else {
    localStorage.setItem(`sentinel_priv_${username}`, b64);
  }
}

export async function loadPrivateKey(
  username: string,
  vaultKey?: CryptoKey | null,
): Promise<string | null> {
  const raw = localStorage.getItem(`sentinel_priv_${username}`);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && parsed.v === 2 && parsed.enc) {
      if (!vaultKey) return null;
      return await decryptWithVaultKey(vaultKey, parsed.enc);
    }
  } catch {}
  return raw;
}

export async function saveSpkPrivate(
  username: string,
  b64: string,
  vaultKey?: CryptoKey | null,
) {
  if (vaultKey) {
    const enc = await encryptWithVaultKey(vaultKey, b64);
    localStorage.setItem(
      `sentinel_spk_${username}`,
      JSON.stringify({ v: 2, enc }),
    );
  } else {
    localStorage.setItem(`sentinel_spk_${username}`, b64);
  }
}

export async function loadSpkPrivate(
  username: string,
  vaultKey?: CryptoKey | null,
): Promise<string | null> {
  const raw = localStorage.getItem(`sentinel_spk_${username}`);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && parsed.v === 2 && parsed.enc) {
      if (!vaultKey) return null;
      return await decryptWithVaultKey(vaultKey, parsed.enc);
    }
  } catch {}
  return raw;
}

export async function saveOpks(
  username: string,
  opks: { pub: string; priv: string }[],
  vaultKey?: CryptoKey | null,
) {
  const raw = JSON.stringify(opks);
  if (vaultKey) {
    const enc = await encryptWithVaultKey(vaultKey, raw);
    localStorage.setItem(
      `sentinel_opks_${username}`,
      JSON.stringify({ v: 2, enc }),
    );
  } else {
    localStorage.setItem(`sentinel_opks_${username}`, raw);
  }
}

export async function loadOpks(
  username: string,
  vaultKey?: CryptoKey | null,
): Promise<{ pub: string; priv: string }[]> {
  const raw = localStorage.getItem(`sentinel_opks_${username}`);
  if (!raw) return [];
  try {
    let jsonStr = raw;
    try {
      const parsed = JSON.parse(raw);
      if (
        parsed &&
        typeof parsed === "object" &&
        parsed.v === 2 &&
        parsed.enc
      ) {
        if (!vaultKey) return [];
        jsonStr = await decryptWithVaultKey(vaultKey, parsed.enc);
      }
    } catch {}
    return JSON.parse(jsonStr);
  } catch {
    return [];
  }
}

export type StoredMessage = {
  id: string;
  type: "user" | "peer";
  text: string;
  timestamp: string;
  peer: string;
};

export type ChatMessage = {
  id: string;
  type: "system" | "user" | "peer" | "command";
  text: string;
  timestamp: Date;
  peer?: string;
  isCmdResult?: boolean;
};

export function chatHistoryKey(username: string, peer: string) {
  return `sentinel_chat_${username}_${peer}`;
}

export async function saveChatHistory(
  username: string,
  peer: string,
  messages: ChatMessage[],
  vaultKey?: CryptoKey | null,
) {
  try {
    const toStore: StoredMessage[] = messages
      .filter(
        (m) => (m.type === "user" || m.type === "peer") && m.peer === peer,
      )
      .map((m) => ({
        id: m.id,
        type: m.type as "user" | "peer",
        text: m.text,
        timestamp: m.timestamp.toISOString(),
        peer: m.peer!,
      }));
    const raw = JSON.stringify(toStore.slice(-500));
    if (vaultKey) {
      const enc = await encryptWithVaultKey(vaultKey, raw);
      localStorage.setItem(
        chatHistoryKey(username, peer),
        JSON.stringify({ v: 2, enc }),
      );
    } else {
      localStorage.setItem(chatHistoryKey(username, peer), raw);
    }
  } catch (e) {
    console.error("Failed to save chat history", e);
  }
}

export async function loadChatHistory(
  username: string,
  peer: string,
  vaultKey?: CryptoKey | null,
): Promise<ChatMessage[]> {
  try {
    const raw = localStorage.getItem(chatHistoryKey(username, peer));
    if (!raw) return [];
    let jsonStr = raw;
    try {
      const parsed = JSON.parse(raw);
      if (
        parsed &&
        typeof parsed === "object" &&
        parsed.v === 2 &&
        parsed.enc
      ) {
        if (!vaultKey) return [];
        jsonStr = await decryptWithVaultKey(vaultKey, parsed.enc);
      }
    } catch {}
    const stored: StoredMessage[] = JSON.parse(jsonStr);
    return stored.map((m) => ({
      id: m.id,
      type: m.type,
      text: m.text,
      timestamp: new Date(m.timestamp),
      peer: m.peer,
    }));
  } catch {
    return [];
  }
}

export function clearChatHistory(username: string, peer: string) {
  localStorage.removeItem(chatHistoryKey(username, peer));
}

export function parseDuration(input: string): number | null {
  const m = input
    .trim()
    .toLowerCase()
    .match(/^(\d+)(s|m|h)$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  if (n <= 0) return null;
  if (m[2] === "s") return n * 1000;
  if (m[2] === "m") return n * 60 * 1000;
  if (m[2] === "h") return n * 60 * 60 * 1000;
  return null;
}

export function formatDuration(ms: number): string {
  if (ms < 60_000) return `${ms / 1000}s`;
  if (ms < 3_600_000) return `${ms / 60_000}m`;
  return `${ms / 3_600_000}h`;
}

export function disappearKey(username: string, peer: string) {
  return `sentinel_disappear_${username}_${peer}`;
}

export function saveDisappearMs(username: string, peer: string, ms: number | null) {
  if (ms === null) {
    localStorage.removeItem(disappearKey(username, peer));
  } else {
    localStorage.setItem(disappearKey(username, peer), String(ms));
  }
}

export function loadDisappearMs(username: string, peer: string): number | null {
  const raw = localStorage.getItem(disappearKey(username, peer));
  if (!raw) return null;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}
