"use client";

import { useState, useRef, useEffect, KeyboardEvent, useCallback } from "react";

const API_BASE = "http://localhost:8080";
const WS_URL = "ws://localhost:8080/ws";

type Message = {
  id: string;
  type: "system" | "user" | "peer" | "command";
  text: string;
  timestamp: Date;
  peer?: string;
};

type ConnStatus = "connecting" | "online" | "offline";

// ─── Crypto helpers ─────────────────────────────────────────────────────────

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
  );
}

async function exportPublicKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("spki", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

async function importPublicKey(b64: string): Promise<CryptoKey> {
  const binary = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "spki",
    binary,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [],
  );
}

async function exportPrivateKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("pkcs8", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

async function importPrivateKey(b64: string): Promise<CryptoKey> {
  const binary = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    binary,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
  );
}

async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  );
}

async function importHmacKey(raw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function hmac(key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
  return crypto.subtle.sign("HMAC", key, data);
}

async function kdfChainKey(
  chainKey: ArrayBuffer,
): Promise<{ messageKey: ArrayBuffer; nextChainKey: ArrayBuffer }> {
  const key = await importHmacKey(chainKey);
  const messageKey = await hmac(key, new Uint8Array([0x01]));
  const nextChainKey = await hmac(key, new Uint8Array([0x02]));
  return { messageKey, nextChainKey };
}

async function kdfRootKey(
  rootKey: ArrayBuffer,
  dhOutput: ArrayBuffer,
): Promise<{ rootKey: ArrayBuffer; chainKey: ArrayBuffer }> {
  const key = await importHmacKey(rootKey);
  const combined = new Uint8Array(dhOutput.byteLength + 32);
  combined.set(new Uint8Array(dhOutput), 0);
  const rootBytes = new Uint8Array(rootKey);
  combined.set(rootBytes.slice(0, 32), dhOutput.byteLength);
  const material = await hmac(key, combined);
  const half = material.byteLength / 2;
  return {
    rootKey: material.slice(0, half),
    chainKey: material.slice(half),
  };
}

async function kdfX3DH(dhOutputs: ArrayBuffer[]): Promise<ArrayBuffer> {
  let total = 0;
  for (const d of dhOutputs) total += d.byteLength;
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const d of dhOutputs) {
    combined.set(new Uint8Array(d), offset);
    offset += d.byteLength;
  }
  const key = await importHmacKey(combined.buffer);
  return hmac(key, new TextEncoder().encode("SentinelX3DH"));
}

async function encryptWithMessageKey(
  messageKey: ArrayBuffer,
  plaintext: string,
): Promise<string> {
  const aesKey = await crypto.subtle.importKey(
    "raw",
    messageKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encoded,
  );
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptWithMessageKey(
  messageKey: ArrayBuffer,
  b64: string,
): Promise<string> {
  const combined = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const data = combined.slice(12);
  const aesKey = await crypto.subtle.importKey(
    "raw",
    messageKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    data,
  );
  return new TextDecoder().decode(decrypted);
}

async function computeSafetyNumber(
  myPublicKeyB64: string,
  theirPublicKeyB64: string,
): Promise<string> {
  const keys = [myPublicKeyB64, theirPublicKeyB64].sort();
  const data = new TextEncoder().encode(keys[0] + keys[1]);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(hash);
  let digits = "";
  for (let i = 0; i < 30; i++) digits += (bytes[i] % 10).toString();
  return digits.match(/.{1,5}/g)!.join(" ");
}

// ─── Vault Cryptography (PBKDF2 + AES-256-GCM) ───────────────────────────────

const CANARY_PAYLOAD = "SENTINEL_VAULT_V1_OK";

async function deriveVaultKey(
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

async function encryptWithVaultKey(
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

async function decryptWithVaultKey(
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

function hasVaultConfigured(username: string): boolean {
  return !!(
    localStorage.getItem(`sentinel_salt_${username}`) &&
    localStorage.getItem(`sentinel_canary_${username}`)
  );
}

async function setupNewVault(
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

async function unlockVault(
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

// ─── Key storage ────────────────────────────────────────────────────────────

async function savePrivateKey(
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

async function loadPrivateKey(
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

async function saveSpkPrivate(
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

async function loadSpkPrivate(
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

async function saveOpks(
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

async function loadOpks(
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

// ─── Session persistence ────────────────────────────────────────────────────

function bufToB64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64ToBuf(b64: string): ArrayBuffer {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
}

type StoredRatchet = {
  rootKey: string;
  sendingChainKey: string | null;
  receivingChainKey: string | null;
  sendN: number;
  recvN: number;
  dhPublicB64: string;
  dhPrivateB64: string;
  remoteDhPublicB64: string | null;
};

type RatchetState = {
  rootKey: ArrayBuffer;
  sendingChainKey: ArrayBuffer | null;
  receivingChainKey: ArrayBuffer | null;
  sendN: number;
  recvN: number;
  dhKeyPair: CryptoKeyPair;
  dhPublicB64: string;
  remoteDhPublicB64: string | null;
  pendingX3DH?: {
    ekPublicB64: string;
    opkUsed: string | null;
  };
};

async function serializeRatchet(state: RatchetState): Promise<StoredRatchet> {
  const dhPrivateB64 = await exportPrivateKey(state.dhKeyPair.privateKey);
  return {
    rootKey: bufToB64(state.rootKey),
    sendingChainKey: state.sendingChainKey
      ? bufToB64(state.sendingChainKey)
      : null,
    receivingChainKey: state.receivingChainKey
      ? bufToB64(state.receivingChainKey)
      : null,
    sendN: state.sendN,
    recvN: state.recvN,
    dhPublicB64: state.dhPublicB64,
    dhPrivateB64,
    remoteDhPublicB64: state.remoteDhPublicB64,
  };
}

async function deserializeRatchet(s: StoredRatchet): Promise<RatchetState> {
  const dhPrivate = await importPrivateKey(s.dhPrivateB64);
  const dhPublic = await importPublicKey(s.dhPublicB64);
  return {
    rootKey: b64ToBuf(s.rootKey),
    sendingChainKey: s.sendingChainKey ? b64ToBuf(s.sendingChainKey) : null,
    receivingChainKey: s.receivingChainKey
      ? b64ToBuf(s.receivingChainKey)
      : null,
    sendN: s.sendN,
    recvN: s.recvN,
    dhKeyPair: { privateKey: dhPrivate, publicKey: dhPublic },
    dhPublicB64: s.dhPublicB64,
    remoteDhPublicB64: s.remoteDhPublicB64,
  };
}

function sessionStorageKey(username: string, peer: string) {
  return `sentinel_session_${username}_${peer}`;
}

async function saveSession(
  username: string,
  peer: string,
  state: RatchetState,
  vaultKey?: CryptoKey | null,
) {
  try {
    const stored = await serializeRatchet(state);
    const raw = JSON.stringify(stored);
    if (vaultKey) {
      const enc = await encryptWithVaultKey(vaultKey, raw);
      localStorage.setItem(
        sessionStorageKey(username, peer),
        JSON.stringify({ v: 2, enc }),
      );
    } else {
      localStorage.setItem(sessionStorageKey(username, peer), raw);
    }
  } catch (e) {
    console.error("Failed to save session", e);
  }
}

async function loadSession(
  username: string,
  peer: string,
  vaultKey?: CryptoKey | null,
): Promise<RatchetState | null> {
  try {
    const raw = localStorage.getItem(sessionStorageKey(username, peer));
    if (!raw) return null;
    let jsonStr = raw;
    try {
      const parsed = JSON.parse(raw);
      if (
        parsed &&
        typeof parsed === "object" &&
        parsed.v === 2 &&
        parsed.enc
      ) {
        if (!vaultKey) return null;
        jsonStr = await decryptWithVaultKey(vaultKey, parsed.enc);
      }
    } catch {}
    return await deserializeRatchet(JSON.parse(jsonStr));
  } catch {
    return null;
  }
}

function listSavedPeers(username: string): string[] {
  const peers: string[] = [];
  const prefix = `sentinel_session_${username}_`;
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith(prefix)) {
      peers.push(key.slice(prefix.length));
    }
  }
  return peers.sort();
}

function clearPeerSession(username: string, peer: string) {
  localStorage.removeItem(sessionStorageKey(username, peer));
}

// ─── Chat history ───────────────────────────────────────────────────────────

type StoredMessage = {
  id: string;
  type: "user" | "peer";
  text: string;
  timestamp: string;
  peer: string;
};

function chatHistoryKey(username: string, peer: string) {
  return `sentinel_chat_${username}_${peer}`;
}

async function saveChatHistory(
  username: string,
  peer: string,
  messages: Message[],
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

async function loadChatHistory(
  username: string,
  peer: string,
  vaultKey?: CryptoKey | null,
): Promise<Message[]> {
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

function clearChatHistory(username: string, peer: string) {
  localStorage.removeItem(chatHistoryKey(username, peer));
}

// ─── Disappearing messages ──────────────────────────────────────────────────

function parseDuration(input: string): number | null {
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

function formatDuration(ms: number): string {
  if (ms < 60_000) return `${ms / 1000}s`;
  if (ms < 3_600_000) return `${ms / 60_000}m`;
  return `${ms / 3_600_000}h`;
}

function disappearKey(username: string, peer: string) {
  return `sentinel_disappear_${username}_${peer}`;
}

function saveDisappearMs(username: string, peer: string, ms: number | null) {
  if (ms === null) {
    localStorage.removeItem(disappearKey(username, peer));
  } else {
    localStorage.setItem(disappearKey(username, peer), String(ms));
  }
}

function loadDisappearMs(username: string, peer: string): number | null {
  const raw = localStorage.getItem(disappearKey(username, peer));
  if (!raw) return null;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

// ─── Component ──────────────────────────────────────────────────────────────

export default function Terminal() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [username, setUsername] = useState<string | null>(null);
  const [activePeer, setActivePeer] = useState<string | null>(null);
  const [contacts, setContacts] = useState<string[]>([]);
  const [connStatus, setConnStatus] = useState<ConnStatus>("connecting");
  const [usersCount, setUsersCount] = useState(0);
  const [mounted, setMounted] = useState(false);
  const [wsAuthed, setWsAuthed] = useState(false);
  const [hasKeys, setHasKeys] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [logOpen, setLogOpen] = useState(false);
  const [disappearMs, setDisappearMs] = useState<number | null>(null);
  const [vaultStatus, setVaultStatus] = useState<
    "locked" | "unlocked" | "shredded" | "none"
  >("none");

  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const usernameRef = useRef<string | null>(null);
  const activePeerRef = useRef<string | null>(null);
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const myPublicKeyB64Ref = useRef<string | null>(null);
  const spkPrivateRef = useRef<CryptoKey | null>(null);
  const opksRef = useRef<{ pub: string; priv: string }[]>([]);
  const safetyNumberRef = useRef<string | null>(null);
  const ratchetRef = useRef<RatchetState | null>(null);
  const ratchetsByPeerRef = useRef<Map<string, RatchetState>>(new Map());
  const disappearTimersRef = useRef<Map<string, number>>(new Map());
  const vaultKeyRef = useRef<CryptoKey | null>(null);

  const pendingCiphertextsRef = useRef<
    Map<string, { id: string; header: any; body: string; from: string }[]>
  >(new Map());

  useEffect(() => {
    usernameRef.current = username;
  }, [username]);

  useEffect(() => {
    activePeerRef.current = activePeer;
  }, [activePeer]);

  const executePanic = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
      wsRef.current = null;
    }

    disappearTimersRef.current.forEach((t) => window.clearTimeout(t));
    disappearTimersRef.current.clear();

    vaultKeyRef.current = null;
    privateKeyRef.current = null;
    myPublicKeyB64Ref.current = null;
    spkPrivateRef.current = null;
    opksRef.current = [];
    safetyNumberRef.current = null;
    ratchetRef.current = null;
    ratchetsByPeerRef.current.clear();
    pendingCiphertextsRef.current.clear();

    try {
      const keysToPurge: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k && k.startsWith("sentinel_")) {
          keysToPurge.push(k);
        }
      }
      for (const k of keysToPurge) {
        localStorage.setItem(k, crypto.randomUUID() + crypto.randomUUID());
        localStorage.removeItem(k);
      }
    } catch {}

    setUsername(null);
    setActivePeer(null);
    setContacts([]);
    setWsAuthed(false);
    setHasKeys(false);
    setDisappearMs(null);
    setVaultStatus("shredded");

    setMessages([
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "════════════════════════════════════════════════════════════════════",
        timestamp: new Date(),
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "🚨 EMERGENCY PANIC PURGE EXECUTED 🚨",
        timestamp: new Date(),
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "• In-memory private keys, ratchets & vault key purged",
        timestamp: new Date(),
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "• Local storage shredded and overwritten",
        timestamp: new Date(),
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "• WebSocket connection forcefully severed",
        timestamp: new Date(),
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "════════════════════════════════════════════════════════════════════",
        timestamp: new Date(),
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "Identity erased from this client. Use /register <user> <passphrase> to establish a new identity.",
        timestamp: new Date(),
      },
    ]);
  }, []);

  useEffect(() => {
    const handleGlobalKey = (e: globalThis.KeyboardEvent) => {
      if (
        (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "x") ||
        (e.ctrlKey && e.altKey && e.key.toLowerCase() === "p")
      ) {
        e.preventDefault();
        executePanic();
      }
    };
    window.addEventListener("keydown", handleGlobalKey);
    return () => window.removeEventListener("keydown", handleGlobalKey);
  }, [executePanic]);

  const scheduleDisappear = useCallback(
    (messageId: string, peer: string, ttlMs: number) => {
      const existing = disappearTimersRef.current.get(messageId);
      if (existing) window.clearTimeout(existing);

      const handle = window.setTimeout(() => {
        setMessages((prev) => {
          const next = prev.filter((m) => m.id !== messageId);
          if (usernameRef.current) {
            void saveChatHistory(
              usernameRef.current,
              peer,
              next,
              vaultKeyRef.current,
            );
          }
          return next;
        });
        disappearTimersRef.current.delete(messageId);
      }, ttlMs);

      disappearTimersRef.current.set(messageId, handle);
    },
    [],
  );

  const addMessage = useCallback(
    (type: Message["type"], text: string, peer?: string) => {
      setMessages((prev) => {
        const next = [
          ...prev,
          {
            id: crypto.randomUUID(),
            type,
            text,
            timestamp: new Date(),
            peer:
              peer ??
              (type === "system"
                ? undefined
                : (activePeerRef.current ?? undefined)),
          },
        ];
        const p = peer ?? (type !== "system" ? activePeerRef.current : null);
        if (p && usernameRef.current && (type === "user" || type === "peer")) {
          void saveChatHistory(
            usernameRef.current,
            p,
            next,
            vaultKeyRef.current,
          );
        }
        return next;
      });
    },
    [],
  );

  const addContact = useCallback((peer: string) => {
    setContacts((prev) => {
      if (prev.includes(peer)) return prev;
      return [...prev, peer].sort();
    });
  }, []);

  const formatTime = (d: Date) =>
    d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

  const checkHealth = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/health`);
      if (res.ok) {
        const data = await res.json();
        setConnStatus("online");
        setUsersCount(data.users_online ?? data.users_registered ?? 0);
        return true;
      }
    } catch {}
    setConnStatus("offline");
    return false;
  }, []);

  const sendWs = useCallback((obj: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(obj));
    }
  }, []);

  async function dhRatchetStep(
    state: RatchetState,
    theirDhPublicB64: string,
  ): Promise<RatchetState> {
    const theirDhPublic = await importPublicKey(theirDhPublicB64);
    const dhOut1 = await deriveSharedSecret(
      state.dhKeyPair.privateKey,
      theirDhPublic,
    );
    const { rootKey: root1, chainKey: recvChain } = await kdfRootKey(
      state.rootKey,
      dhOut1,
    );
    const newKeyPair = await generateKeyPair();
    const newPubB64 = await exportPublicKey(newKeyPair.publicKey);
    const dhOut2 = await deriveSharedSecret(
      newKeyPair.privateKey,
      theirDhPublic,
    );
    const { rootKey: root2, chainKey: sendChain } = await kdfRootKey(
      root1,
      dhOut2,
    );
    return {
      rootKey: root2,
      sendingChainKey: sendChain,
      receivingChainKey: recvChain,
      sendN: 0,
      recvN: 0,
      dhKeyPair: newKeyPair,
      dhPublicB64: newPubB64,
      remoteDhPublicB64: theirDhPublicB64,
    };
  }

  async function completeX3DHAsReceiver(
    senderIkPublicB64: string,
    ekPublicB64: string,
    opkPublicB64: string | null,
  ): Promise<ArrayBuffer | null> {
    if (!privateKeyRef.current || !spkPrivateRef.current) return null;

    const senderIK = await importPublicKey(senderIkPublicB64);
    const ekPublic = await importPublicKey(ekPublicB64);
    const dhOutputs: ArrayBuffer[] = [];

    dhOutputs.push(await deriveSharedSecret(spkPrivateRef.current, senderIK));
    dhOutputs.push(await deriveSharedSecret(privateKeyRef.current, ekPublic));
    dhOutputs.push(await deriveSharedSecret(spkPrivateRef.current, ekPublic));

    if (opkPublicB64) {
      const opkEntry = opksRef.current.find((o) => o.pub === opkPublicB64);
      if (opkEntry) {
        const opkPriv = await importPrivateKey(opkEntry.priv);
        dhOutputs.push(await deriveSharedSecret(opkPriv, ekPublic));
      }
    }

    return kdfX3DH(dhOutputs);
  }

  const tryDecryptPending = useCallback(
    async (peer: string) => {
      const pending = pendingCiphertextsRef.current.get(peer);
      if (!pending || pending.length === 0) return;

      const state = ratchetsByPeerRef.current.get(peer) || ratchetRef.current;
      if (!state) return;

      const remaining: typeof pending = [];

      for (const item of pending) {
        try {
          let s: RatchetState = state;
          const { header, body } = item;

          if (
            header.dh &&
            s.remoteDhPublicB64 &&
            header.dh !== s.remoteDhPublicB64
          ) {
            s = await dhRatchetStep(s, header.dh);
          } else if (header.dh && !s.remoteDhPublicB64) {
            s = { ...s, remoteDhPublicB64: header.dh };
          }

          if (!s.receivingChainKey) {
            remaining.push(item);
            continue;
          }

          let receivingChainKey: ArrayBuffer = s.receivingChainKey;
          let recvN = s.recvN;

          while (recvN < header.n) {
            const { nextChainKey } = await kdfChainKey(receivingChainKey);
            receivingChainKey = nextChainKey;
            recvN++;
          }

          if (recvN !== header.n) {
            remaining.push(item);
            continue;
          }

          const { messageKey, nextChainKey } =
            await kdfChainKey(receivingChainKey);
          const plaintext = await decryptWithMessageKey(messageKey, body);

          const newState: RatchetState = {
            ...s,
            receivingChainKey: nextChainKey,
            recvN: recvN + 1,
          };

          ratchetsByPeerRef.current.set(peer, newState);
          if (activePeerRef.current === peer) {
            ratchetRef.current = newState;
          }

          if (usernameRef.current) {
            await saveSession(usernameRef.current, peer, newState);
          }

          setMessages((prev) => {
            const next = prev.map((m) =>
              m.id === item.id
                ? {
                    ...m,
                    type: "peer" as const,
                    text: `[${item.from}] ${plaintext}`,
                    peer,
                  }
                : m,
            );
            if (usernameRef.current) {
              saveChatHistory(usernameRef.current, peer, next);
            }
            return next;
          });

          const ttl = typeof header.ttl === "number" ? header.ttl : null;
          if (ttl && ttl > 0) {
            scheduleDisappear(item.id, peer, ttl);
          }
        } catch {
          remaining.push(item);
        }
      }

      if (remaining.length === 0) {
        pendingCiphertextsRef.current.delete(peer);
      } else {
        pendingCiphertextsRef.current.set(peer, remaining);
      }
    },
    [scheduleDisappear],
  );

  const loadPeerHistoryIntoView = useCallback(async (peer: string) => {
    if (!usernameRef.current) return;
    const history = await loadChatHistory(
      usernameRef.current,
      peer,
      vaultKeyRef.current,
    );
    setMessages((prev) => {
      const systems = prev.filter((m) => m.type === "system");
      const otherPeers = prev.filter(
        (m) => m.type !== "system" && m.peer !== peer,
      );
      return [...systems, ...otherPeers, ...history];
    });
  }, []);

  const switchToPeer = useCallback(
    async (peer: string) => {
      if (activePeerRef.current && ratchetRef.current && usernameRef.current) {
        ratchetsByPeerRef.current.set(
          activePeerRef.current,
          ratchetRef.current,
        );
        await saveSession(
          usernameRef.current,
          activePeerRef.current,
          ratchetRef.current,
        );
      }

      setActivePeer(peer);
      addContact(peer);

      if (usernameRef.current) {
        setDisappearMs(loadDisappearMs(usernameRef.current, peer));
      }

      let state = ratchetsByPeerRef.current.get(peer);
      if (!state && usernameRef.current) {
        const loaded = await loadSession(usernameRef.current, peer);
        if (loaded) {
          state = loaded;
          ratchetsByPeerRef.current.set(peer, loaded);
        }
      }

      ratchetRef.current = state || null;
      loadPeerHistoryIntoView(peer);

      if (state) {
        addMessage("system", `Switched to ${peer} (session active).`);
        await tryDecryptPending(peer);
      } else {
        addMessage(
          "system",
          `Switched to ${peer}. No session yet — use /new ${peer} or wait for their message.`,
        );
      }

      inputRef.current?.focus();
    },
    [addContact, addMessage, tryDecryptPending, loadPeerHistoryIntoView],
  );

  const connectWs = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnStatus("online");
        addMessage("system", "Connected to Sentinel backend (WebSocket)");
        if (usernameRef.current) {
          ws.send(
            JSON.stringify({ type: "auth", username: usernameRef.current }),
          );
        }
      };

      ws.onmessage = async (evt) => {
        try {
          const msg = JSON.parse(evt.data);

          switch (msg.type) {
            case "auth_ok":
              setWsAuthed(true);
              addMessage(
                "system",
                `WebSocket authenticated as ${msg.username}`,
              );
              break;

            case "auth_error":
              setWsAuthed(false);
              addMessage("system", `Auth error: ${msg.message}`);
              break;

            case "message": {
              try {
                const payload = JSON.parse(msg.text);
                const { header, body } = payload;
                const from = msg.from as string;
                addContact(from);

                let state =
                  ratchetsByPeerRef.current.get(from) ||
                  (activePeerRef.current === from ? ratchetRef.current : null);

                if (!state && usernameRef.current) {
                  const restored = await loadSession(usernameRef.current, from);
                  if (restored) {
                    state = restored;
                    ratchetsByPeerRef.current.set(from, restored);
                    if (activePeerRef.current === from) {
                      ratchetRef.current = restored;
                    }
                    addMessage(
                      "system",
                      `Restored encrypted session with ${from}.`,
                      from,
                    );
                    await tryDecryptPending(from);
                  }
                }

                if (header?.x3dh && !state) {
                  if (!header.x3dh.ik) {
                    addMessage(
                      "peer",
                      `[${from}] (encrypted – missing identity key)`,
                      from,
                    );
                    break;
                  }
                  const sk = await completeX3DHAsReceiver(
                    header.x3dh.ik,
                    header.x3dh.ek,
                    header.x3dh.opk || null,
                  );
                  if (sk) {
                    const dhKeyPair = await generateKeyPair();
                    const dhPublicB64 = await exportPublicKey(
                      dhKeyPair.publicKey,
                    );
                    const key = await importHmacKey(sk);
                    const initialChain = await hmac(
                      key,
                      new TextEncoder().encode("SentinelInitChain"),
                    );
                    state = {
                      rootKey: sk,
                      sendingChainKey: initialChain,
                      receivingChainKey: initialChain,
                      sendN: 0,
                      recvN: 0,
                      dhKeyPair,
                      dhPublicB64,
                      remoteDhPublicB64: header.dh || null,
                    };
                    ratchetsByPeerRef.current.set(from, state);
                    if (
                      !activePeerRef.current ||
                      activePeerRef.current === from
                    ) {
                      ratchetRef.current = state;
                      setActivePeer(from);
                    }
                    if (usernameRef.current) {
                      await saveSession(usernameRef.current, from, state);
                    }
                    addMessage(
                      "system",
                      `X3DH session opened with ${from}.`,
                      from,
                    );
                    await tryDecryptPending(from);
                  }
                }

                if (!state) {
                  const id = crypto.randomUUID();
                  const placeholder = `[${from}] (encrypted – open chat or /new ${from})`;
                  setMessages((prev) => [
                    ...prev,
                    {
                      id,
                      type: "peer" as const,
                      text: placeholder,
                      timestamp: new Date(),
                      peer: from,
                    },
                  ]);
                  const list = pendingCiphertextsRef.current.get(from) || [];
                  list.push({ id, header, body, from });
                  pendingCiphertextsRef.current.set(from, list);
                  break;
                }

                let s: RatchetState = state;

                if (
                  header.dh &&
                  s.remoteDhPublicB64 &&
                  header.dh !== s.remoteDhPublicB64
                ) {
                  s = await dhRatchetStep(s, header.dh);
                } else if (header.dh && !s.remoteDhPublicB64) {
                  s = { ...s, remoteDhPublicB64: header.dh };
                }

                if (!s.receivingChainKey) {
                  addMessage(
                    "peer",
                    `[${from}] (no receiving chain yet)`,
                    from,
                  );
                  break;
                }

                let receivingChainKey: ArrayBuffer = s.receivingChainKey;
                let recvN = s.recvN;

                while (recvN < header.n) {
                  const { nextChainKey } = await kdfChainKey(receivingChainKey);
                  receivingChainKey = nextChainKey;
                  recvN++;
                }

                if (recvN !== header.n) {
                  addMessage(
                    "peer",
                    `[${from}] (message number mismatch)`,
                    from,
                  );
                  break;
                }

                const { messageKey, nextChainKey } =
                  await kdfChainKey(receivingChainKey);
                const plaintext = await decryptWithMessageKey(messageKey, body);

                const newState: RatchetState = {
                  ...s,
                  receivingChainKey: nextChainKey,
                  recvN: recvN + 1,
                };

                ratchetsByPeerRef.current.set(from, newState);
                if (activePeerRef.current === from) {
                  ratchetRef.current = newState;
                }

                if (usernameRef.current) {
                  await saveSession(usernameRef.current, from, newState);
                }

                const msgId = crypto.randomUUID();
                setMessages((prev) => {
                  const next = [
                    ...prev,
                    {
                      id: msgId,
                      type: "peer" as const,
                      text: `[${from}] ${plaintext}`,
                      timestamp: new Date(),
                      peer: from,
                    },
                  ];
                  if (usernameRef.current) {
                    saveChatHistory(usernameRef.current, from, next);
                  }
                  return next;
                });

                const ttl = typeof header.ttl === "number" ? header.ttl : null;
                if (ttl && ttl > 0) {
                  scheduleDisappear(msgId, from, ttl);
                }
              } catch (err) {
                console.error(err);
                addMessage(
                  "peer",
                  `[${msg.from}] Couldn’t decrypt this message. Run /reset ${msg.from} then /new ${msg.from} to start a fresh secure chat.`,
                  msg.from,
                );
              }
              break;
            }

            case "delivered":
              break;

            case "system":
              addMessage("system", msg.message);
              break;

            case "pong":
              break;

            default:
              break;
          }
        } catch {
          // ignore
        }
      };

      ws.onclose = () => {
        setConnStatus("offline");
        setWsAuthed(false);
        wsRef.current = null;
        setTimeout(connectWs, 5000);
      };

      ws.onerror = () => setConnStatus("offline");
    } catch {
      setConnStatus("offline");
    }
  }, [addMessage, addContact, tryDecryptPending, scheduleDisappear]);

  useEffect(() => {
    setMounted(true);
    setMessages([
      {
        id: "1",
        type: "system",
        text: "SENTINEL v0.2.0 — Secure Terminal Messaging",
        timestamp: new Date(),
      },
      {
        id: "2",
        type: "system",
        text: "X3DH + Double Ratchet • History • Disappearing messages",
        timestamp: new Date(),
      },
      {
        id: "3",
        type: "system",
        text: "Type /help for commands. Click a contact to switch chat.",
        timestamp: new Date(),
      },
      {
        id: "4",
        type: "system",
        text: "────────────────────────────────────────────────────────────",
        timestamp: new Date(),
      },
    ]);

    (async () => {
      const ok = await checkHealth();
      if (ok) {
        addMessage("system", "Backend online — http://localhost:8080");
        connectWs();
      } else {
        addMessage(
          "system",
          "Backend offline. Start it with:  cd backend && cargo run",
        );
      }
    })();

    inputRef.current?.focus();
    return () => {
      wsRef.current?.close();
      disappearTimersRef.current.forEach((t) => window.clearTimeout(t));
      disappearTimersRef.current.clear();
    };
  }, [checkHealth, connectWs, addMessage]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activePeer]);

  const systemMessages = messages.filter((m) => m.type === "system");
  const chatMessages = messages.filter((m) => {
    if (m.type === "system") return false;
    if (!activePeer) return false;
    return m.peer === activePeer;
  });

  // ─── Commands ─────────────────────────────────────────────────────────────

  const handleCommand = async (cmd: string) => {
    const parts = cmd.trim().split(/\s+/);
    const command = parts[0].toLowerCase();

    switch (command) {
      case "/help":
        addMessage(
          "system",
          `Available commands:
  /help                  Show this help
  /register <username>   Create identity + prekeys
  /login <username>      Login and load keys + history
  /new <user>            Start or restore session with user
  /chats                 List contacts / sessions
  /disappear <time|off>  Auto-delete msgs (30s, 5m, 1h, off)
  /reset <user>            Reset broken secure session with user
  /verify                Show Safety Number
  /clear                 Clear current chat history
  /status                Show status
  /logout                End session

  Chat history is saved on this device.
  Disappearing messages delete on both sides after the timer.`,
        );
        break;

      case "/chats": {
        if (contacts.length === 0) {
          addMessage("system", "No contacts yet. Use /new <user> to start.");
        } else {
          addMessage(
            "system",
            `Contacts:\n${contacts
              .map((c) => (c === activePeer ? `  → ${c} (active)` : `    ${c}`))
              .join("\n")}`,
          );
        }
        break;
      }

      case "/disappear": {
        if (!activePeer || !username) {
          addMessage("system", "Open a chat first, then use /disappear <time>");
          break;
        }
        if (!parts[1] || parts[1].toLowerCase() === "off") {
          setDisappearMs(null);
          saveDisappearMs(username, activePeer, null);
          addMessage("system", `Disappearing messages OFF for ${activePeer}.`);
          break;
        }
        const ms = parseDuration(parts[1]);
        if (ms === null) {
          addMessage(
            "system",
            "Usage: /disappear <time>  e.g. 30s, 5m, 1h  |  /disappear off",
          );
          break;
        }
        setDisappearMs(ms);
        saveDisappearMs(username, activePeer, ms);
        addMessage(
          "system",
          `Disappearing messages ON for ${activePeer}: ${formatDuration(ms)}`,
        );
        break;
      }

      case "/reset": {
        if (!username) {
          addMessage("system", "Login first.");
          break;
        }
        const peer = (parts[1] || activePeer || "").toLowerCase();
        if (!peer) {
          addMessage("system", "Usage: /reset <username>");
          break;
        }

        // Clear in-memory session
        ratchetsByPeerRef.current.delete(peer);
        if (activePeerRef.current === peer) {
          ratchetRef.current = null;
        }
        pendingCiphertextsRef.current.delete(peer);
        safetyNumberRef.current = null;

        // Clear saved session on disk
        clearPeerSession(username, peer);

        addMessage(
          "system",
          `Secure session with ${peer} was reset on this device.`,
        );
        addMessage(
          "system",
          `Next: run /new ${peer} (only one of you), then send a message to open a new chat.`,
        );
        break;
      }

      case "/register": {
        if (!parts[1]) {
          addMessage("system", "Usage: /register <username>");
          break;
        }
        const name = parts[1].toLowerCase();
        addMessage("system", `Registering "${name}"...`);

        try {
          addMessage(
            "system",
            "Generating identity + signed prekey + one-time prekeys...",
          );

          const identity = await generateKeyPair();
          const publicKeyB64 = await exportPublicKey(identity.publicKey);
          const privateKeyB64 = await exportPrivateKey(identity.privateKey);

          const spk = await generateKeyPair();
          const spkPub = await exportPublicKey(spk.publicKey);
          const spkPriv = await exportPrivateKey(spk.privateKey);

          const opks: { pub: string; priv: string }[] = [];
          for (let i = 0; i < 5; i++) {
            const kp = await generateKeyPair();
            opks.push({
              pub: await exportPublicKey(kp.publicKey),
              priv: await exportPrivateKey(kp.privateKey),
            });
          }

          await savePrivateKey(name, privateKeyB64, vaultKeyRef.current);
          await saveSpkPrivate(name, spkPriv, vaultKeyRef.current);
          await saveOpks(name, opks, vaultKeyRef.current);

          privateKeyRef.current = identity.privateKey;
          myPublicKeyB64Ref.current = publicKeyB64;
          spkPrivateRef.current = spk.privateKey;
          opksRef.current = opks;
          setHasKeys(true);

          const res = await fetch(`${API_BASE}/api/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: name,
              public_key: publicKeyB64,
            }),
          });
          const data = await res.json();

          if (!data.success) {
            addMessage("system", `Error: ${data.message}`);
            break;
          }

          const preRes = await fetch(`${API_BASE}/api/prekeys`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: name,
              signed_prekey: spkPub,
              one_time_prekeys: opks.map((o) => o.pub),
            }),
          });
          const preData = await preRes.json();

          setUsername(data.user.username);
          addMessage("system", `Identity created: ${data.user.username}`);
          addMessage(
            "system",
            preData.success
              ? "Prekeys uploaded (X3DH ready)."
              : "Warning: prekey upload failed.",
          );

          const saved = listSavedPeers(data.user.username);
          if (saved.length > 0) {
            setContacts(saved);
            addMessage("system", `Found ${saved.length} saved session(s).`);
          }

          sendWs({ type: "auth", username: data.user.username });
          setUsersCount((c) => c + 1);
        } catch (err) {
          console.error(err);
          addMessage("system", "Failed to register. Is the backend running?");
          setConnStatus("offline");
        }
        break;
      }

      case "/login": {
        if (!parts[1]) {
          addMessage("system", "Usage: /login <username>");
          break;
        }
        const name = parts[1].toLowerCase();
        addMessage("system", `Logging in as "${name}"...`);

        try {
          const res = await fetch(`${API_BASE}/api/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: name }),
          });
          const data = await res.json();

          if (!data.success) {
            addMessage("system", `Error: ${data.message}`);
            break;
          }

          const privB64 = await loadPrivateKey(name, vaultKeyRef.current);
          if (!privB64) {
            addMessage("system", "No local private key found on this device.");
            setUsername(data.user.username);
            if (data.user.public_key)
              myPublicKeyB64Ref.current = data.user.public_key;
            sendWs({ type: "auth", username: data.user.username });
            break;
          }

          privateKeyRef.current = await importPrivateKey(privB64);
          if (data.user.public_key)
            myPublicKeyB64Ref.current = data.user.public_key;

          const spkB64 = await loadSpkPrivate(name, vaultKeyRef.current);
          if (spkB64) spkPrivateRef.current = await importPrivateKey(spkB64);
          opksRef.current = await loadOpks(name, vaultKeyRef.current);

          setHasKeys(true);
          setUsername(data.user.username);

          const saved = listSavedPeers(name);
          setContacts(saved);

          addMessage(
            "system",
            `Logged in as ${data.user.username} (id: ${data.user.id})`,
          );
          addMessage(
            "system",
            saved.length > 0
              ? `Loaded ${saved.length} contact(s). Click one to restore chat history.`
              : `Keys loaded. Use /new <peer> to start a chat.`,
          );
          sendWs({ type: "auth", username: data.user.username });
        } catch {
          addMessage("system", "Failed to reach backend.");
          setConnStatus("offline");
        }
        break;
      }

      case "/new": {
        if (!parts[1]) {
          addMessage("system", "Usage: /new <username>");
          break;
        }
        if (!username || !privateKeyRef.current || !myPublicKeyB64Ref.current) {
          addMessage("system", "Register or login first.");
          break;
        }

        const peer = parts[1].toLowerCase();
        if (peer === username) {
          addMessage("system", "Cannot chat with yourself.");
          break;
        }

        const existing =
          ratchetsByPeerRef.current.get(peer) ||
          (await loadSession(username, peer));

        if (existing) {
          ratchetsByPeerRef.current.set(peer, existing);
          ratchetRef.current = existing;
          setActivePeer(peer);
          addContact(peer);
          setDisappearMs(loadDisappearMs(username, peer));
          loadPeerHistoryIntoView(peer);
          addMessage(
            "system",
            `Restored existing session with ${peer}. Ready to chat.`,
          );
          await tryDecryptPending(peer);
          break;
        }

        addMessage("system", `Fetching prekey bundle for ${peer}...`);

        try {
          const res = await fetch(`${API_BASE}/api/prekey-bundle/${peer}`);
          const bundle = await res.json();

          if (
            !bundle.success ||
            !bundle.identity_key ||
            !bundle.signed_prekey
          ) {
            addMessage(
              "system",
              `No prekeys for '${peer}'. They must /register first.`,
            );
            break;
          }

          const theirIK = await importPublicKey(bundle.identity_key);
          const theirSPK = await importPublicKey(bundle.signed_prekey);
          const ek = await generateKeyPair();
          const ekPub = await exportPublicKey(ek.publicKey);

          const dhOutputs: ArrayBuffer[] = [];
          dhOutputs.push(
            await deriveSharedSecret(privateKeyRef.current, theirSPK),
          );
          dhOutputs.push(await deriveSharedSecret(ek.privateKey, theirIK));
          dhOutputs.push(await deriveSharedSecret(ek.privateKey, theirSPK));

          let opkUsed: string | null = null;
          if (bundle.one_time_prekey) {
            const theirOPK = await importPublicKey(bundle.one_time_prekey);
            dhOutputs.push(await deriveSharedSecret(ek.privateKey, theirOPK));
            opkUsed = bundle.one_time_prekey;
          }

          const rootKey = await kdfX3DH(dhOutputs);
          const dhKeyPair = await generateKeyPair();
          const dhPublicB64 = await exportPublicKey(dhKeyPair.publicKey);
          const key = await importHmacKey(rootKey);
          const initialChain = await hmac(
            key,
            new TextEncoder().encode("SentinelInitChain"),
          );

          const newState: RatchetState = {
            rootKey,
            sendingChainKey: initialChain,
            receivingChainKey: initialChain,
            sendN: 0,
            recvN: 0,
            dhKeyPair,
            dhPublicB64,
            remoteDhPublicB64: null,
            pendingX3DH: { ekPublicB64: ekPub, opkUsed },
          };

          ratchetsByPeerRef.current.set(peer, newState);
          ratchetRef.current = newState;
          await saveSession(username, peer, newState);

          const safety = await computeSafetyNumber(
            myPublicKeyB64Ref.current,
            bundle.identity_key,
          );
          safetyNumberRef.current = safety;

          setActivePeer(peer);
          addContact(peer);
          setDisappearMs(loadDisappearMs(username, peer));
          loadPeerHistoryIntoView(peer);
          addMessage(
            "system",
            `X3DH + Double Ratchet session started with ${peer}.`,
          );
          addMessage("system", "────────────────────────────────────────");
          addMessage("system", "SAFETY NUMBER (compare with your contact):");
          addMessage("system", safety);
          addMessage("system", "────────────────────────────────────────");
          await tryDecryptPending(peer);
        } catch (err) {
          console.error(err);
          addMessage("system", `Failed to set up session with ${peer}.`);
        }
        break;
      }

      case "/verify": {
        if (!activePeer || !safetyNumberRef.current) {
          addMessage("system", "No active chat. Use /new <user> first.");
          break;
        }
        addMessage("system", "────────────────────────────────────────");
        addMessage("system", `Safety Number with ${activePeer}:`);
        addMessage("system", safetyNumberRef.current);
        addMessage("system", "────────────────────────────────────────");
        break;
      }

      case "/status":
        addMessage(
          "system",
          `Status:
  User:            ${username || "not registered"}
  Active chat:     ${activePeer || "none"}
  Contacts:        ${contacts.length}
  Backend:         ${connStatus.toUpperCase()}
  WebSocket auth:  ${wsAuthed ? "yes" : "no"}
  Local keys:      ${hasKeys ? "loaded" : "none"}
  Ratchet:         ${ratchetRef.current ? "active" : "none"}
  Disappear:       ${disappearMs ? formatDuration(disappearMs) : "off"}
  Chat history:    persisted on this device
  Encryption:      X3DH + Double Ratchet + AES-GCM
  WebSocket:       ${
    wsRef.current?.readyState === WebSocket.OPEN ? "connected" : "disconnected"
  }`,
        );
        break;

      case "/clear":
        if (activePeer && username) {
          clearChatHistory(username, activePeer);
          setMessages((prev) =>
            prev.filter((m) => m.type === "system" || m.peer !== activePeer),
          );
          addMessage("system", `Cleared chat history with ${activePeer}.`);
        } else {
          addMessage("system", "No active chat to clear.");
        }
        break;

      case "/logout":
        disappearTimersRef.current.forEach((t) => window.clearTimeout(t));
        disappearTimersRef.current.clear();
        setDisappearMs(null);
        setUsername(null);
        setActivePeer(null);
        setContacts([]);
        setWsAuthed(false);
        setHasKeys(false);
        privateKeyRef.current = null;
        myPublicKeyB64Ref.current = null;
        spkPrivateRef.current = null;
        opksRef.current = [];
        safetyNumberRef.current = null;
        ratchetRef.current = null;
        ratchetsByPeerRef.current.clear();
        addMessage(
          "system",
          "Session ended. Keys, sessions, and chat history kept on this device.",
        );
        break;

      case "/panic":
        executePanic();
        break;

      default:
        if (cmd.startsWith("/")) {
          addMessage("system", `Unknown command: ${command}. Type /help`);
        } else if (!username) {
          addMessage("system", "You must /register or /login first.");
        } else if (!activePeer) {
          addMessage(
            "system",
            "No active chat. Click a contact or use /new <username>.",
          );
        } else if (!ratchetRef.current?.sendingChainKey) {
          addMessage(
            "system",
            "No session with this peer. Use /new <peer> first.",
          );
        } else if (!wsAuthed) {
          addMessage("system", "WebSocket not authenticated yet.");
        } else {
          try {
            const state = ratchetRef.current;
            const sendingChainKey = state.sendingChainKey as ArrayBuffer;
            const { messageKey, nextChainKey } =
              await kdfChainKey(sendingChainKey);
            const body = await encryptWithMessageKey(messageKey, cmd);

            const header: Record<string, unknown> = {
              dh: state.dhPublicB64,
              n: state.sendN,
            };

            if (state.pendingX3DH && state.sendN === 0) {
              header.x3dh = {
                ik: myPublicKeyB64Ref.current,
                ek: state.pendingX3DH.ekPublicB64,
                opk: state.pendingX3DH.opkUsed,
              };
            }

            if (disappearMs) {
              header.ttl = disappearMs;
            }

            const msgId = crypto.randomUUID();
            setMessages((prev) => {
              const next = [
                ...prev,
                {
                  id: msgId,
                  type: "user" as const,
                  text: cmd,
                  timestamp: new Date(),
                  peer: activePeer,
                },
              ];
              saveChatHistory(username, activePeer, next);
              return next;
            });

            if (disappearMs) {
              scheduleDisappear(msgId, activePeer, disappearMs);
            }

            sendWs({
              type: "message",
              to: activePeer,
              text: JSON.stringify({ header, body }),
            });

            const newState: RatchetState = {
              ...state,
              sendingChainKey: nextChainKey,
              sendN: state.sendN + 1,
              pendingX3DH: state.sendN === 0 ? undefined : state.pendingX3DH,
            };

            ratchetRef.current = newState;
            ratchetsByPeerRef.current.set(activePeer, newState);

            if (username && activePeer) {
              await saveSession(username, activePeer, newState);
            }
          } catch (err) {
            console.error(err);
            addMessage("system", "Failed to encrypt message.");
          }
        }
    }
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && input.trim()) {
      const value = input.trim();
      setInput("");
      handleCommand(value);
    }
  };

  if (!mounted) {
    return (
      <div className="flex flex-col h-screen bg-[#0a0a0a] text-[#00ff41] p-4 font-mono">
        <div className="opacity-50">Loading Sentinel...</div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-[#0a0a0a] text-[#00ff41] font-mono overflow-hidden">
      {sidebarOpen && (
        <div className="w-48 shrink-0 border-r border-[#003300] flex flex-col bg-[#050505]">
          <div className="px-3 py-2 border-b border-[#003300] flex items-center justify-between">
            <span className="text-[#00ff41] font-bold text-sm tracking-wider">
              CONTACTS
            </span>
            <button
              onClick={() => setSidebarOpen(false)}
              className="text-[#003300] hover:text-[#00aa2a] text-xs"
              title="Hide sidebar"
            >
              «
            </button>
          </div>

          <div className="flex-1 overflow-y-auto py-1">
            {contacts.length === 0 ? (
              <div className="px-3 py-4 text-[#003300] text-xs">
                No contacts yet.
                <br />
                Use /new &lt;user&gt;
              </div>
            ) : (
              contacts.map((c) => (
                <button
                  key={c}
                  onClick={() => switchToPeer(c)}
                  className={`w-full text-left px-3 py-1.5 text-sm truncate transition-colors ${
                    c === activePeer
                      ? "bg-[#003300] text-[#00ff41]"
                      : "text-[#00aa2a] hover:bg-[#001a00] hover:text-[#00ff41]"
                  }`}
                >
                  {c === activePeer ? "▸ " : "  "}
                  {c}
                </button>
              ))
            )}
          </div>

          <div className="px-3 py-2 border-t border-[#003300] text-[10px] text-[#003300]">
            {username ? `${username}` : "not logged in"}
          </div>
        </div>
      )}

      <div className="flex-1 flex flex-col min-w-0">
        <div className="flex items-center justify-between border-b border-[#003300] px-4 py-2 select-none shrink-0">
          <div className="flex items-center gap-3">
            {!sidebarOpen && (
              <button
                onClick={() => setSidebarOpen(true)}
                className="text-[#00aa2a] hover:text-[#00ff41] text-sm"
                title="Show contacts"
              >
                »
              </button>
            )}
            <span className="text-[#00ff41] font-bold tracking-wider">
              SENTINEL
            </span>
            <span className="text-[#003300]">|</span>
            <span
              className={
                connStatus === "online"
                  ? "text-[#00ff41]"
                  : connStatus === "connecting"
                    ? "text-[#ffb000]"
                    : "text-[#ff4444]"
              }
            >
              ● {connStatus}
            </span>
            {activePeer && (
              <>
                <span className="text-[#003300]">|</span>
                <span className="text-[#00ccff]">→ {activePeer}</span>
                <span className="text-[#00aa2a] text-xs">E2EE</span>
                {disappearMs && (
                  <span className="text-[#ffb000] text-xs">
                    TTL {formatDuration(disappearMs)}
                  </span>
                )}
              </>
            )}
          </div>
          <div className="text-sm">
            {username ? (
              <span>
                <span className="text-[#ffb000]">{username}</span>@sentinel
              </span>
            ) : (
              <span className="opacity-60">not authenticated</span>
            )}
          </div>
        </div>

        <div className="shrink-0 border-b border-[#003300]">
          <button
            onClick={() => setLogOpen((o) => !o)}
            className="w-full flex items-center gap-2 px-4 py-1.5 text-xs text-[#00aa2a] hover:bg-[#001a00] select-none"
          >
            <span>{logOpen ? "▼" : "▶"}</span>
            <span>System log</span>
            <span className="text-[#003300]">({systemMessages.length})</span>
          </button>

          {logOpen && (
            <div className="max-h-40 overflow-y-auto px-4 pb-2 space-y-0.5 text-xs bg-[#050505]">
              {systemMessages.length === 0 ? (
                <div className="text-[#003300] py-1">No system messages</div>
              ) : (
                systemMessages.map((msg) => (
                  <div key={msg.id} className="flex gap-2 text-[#00aa2a]">
                    <span className="text-[#003300] shrink-0 w-16 text-right">
                      {formatTime(msg.timestamp)}
                    </span>
                    <span className="whitespace-pre-wrap opacity-80">
                      {msg.text}
                    </span>
                  </div>
                ))
              )}
            </div>
          )}
        </div>

        <div className="flex-1 overflow-y-auto px-4 py-2 text-sm leading-relaxed space-y-1">
          {!activePeer ? (
            <div className="text-[#003300] text-sm py-8 text-center">
              Select a contact or use /new &lt;user&gt; to start chatting
            </div>
          ) : chatMessages.length === 0 ? (
            <div className="text-[#003300] text-sm py-8 text-center">
              No messages with {activePeer} yet
            </div>
          ) : (
            chatMessages.map((msg) => (
              <div key={msg.id} className="flex gap-2">
                <span className="text-[#003300] shrink-0 w-20 text-right">
                  {formatTime(msg.timestamp)}
                </span>
                <span className="shrink-0 w-16">
                  {msg.type === "user" && (
                    <span className="text-[#ffb000]">you</span>
                  )}
                  {msg.type === "peer" && (
                    <span className="text-[#00ccff]">peer</span>
                  )}
                </span>
                <span
                  className={
                    msg.type === "user" ? "text-[#00ff41]" : "text-[#00ccff]"
                  }
                >
                  {msg.text}
                </span>
              </div>
            ))
          )}
          <div ref={bottomRef} />
        </div>

        <div className="border-t border-[#003300] px-4 py-3 flex items-center gap-2 shrink-0">
          <span className="text-[#00ff41] shrink-0">
            {username ? username : "anon"}
            <span className="text-[#00aa2a]">@sentinel</span>
            <span className="text-[#00ff41]">:~$</span>
          </span>
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            className="flex-1 bg-transparent border-none outline-none text-[#00ff41] caret-[#00ff41]"
            placeholder={
              activePeer
                ? disappearMs
                  ? `message ${activePeer} (TTL ${formatDuration(disappearMs)})...`
                  : `message ${activePeer}...`
                : "type a command or /new <user>..."
            }
            spellCheck={false}
            autoComplete="off"
            autoCorrect="off"
          />
          <span className="text-[#00ff41]">█</span>
        </div>

        <div className="px-4 py-1 text-[10px] text-[#003300] flex justify-between select-none shrink-0">
          <span>
            {connStatus === "online" ? "BACKEND ONLINE" : "BACKEND OFFLINE"} •
            disappearing msgs
          </span>
          <span>v0.2.0-dev</span>
        </div>
      </div>
    </div>
  );
}
