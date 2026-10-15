"use client";

import { useState, useRef, useEffect, KeyboardEvent, useCallback } from "react";
import QRCode from "qrcode";
import {
  uploadZeroKnowledgeVault,
  downloadZeroKnowledgeVault,
  getFirebaseStatus,
  saveRuntimeFirebaseConfig,
  clearRuntimeFirebaseConfig,
  checkCloudVaultExists,
  CloudVaultPayload,
} from "@/lib/firebaseVault";
import {
  getActiveServerConfig,
  saveRuntimeServerConfig,
  clearRuntimeServerConfig,
  ServerConfig,
} from "@/lib/serverConfig";

type Message = {
  id: string;
  type: "system" | "user" | "peer" | "command";
  text: string;
  timestamp: Date;
  peer?: string;
  isCmdResult?: boolean;
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

// ─── Constant-Length Message Padding (Traffic Analysis Defense) ─────────────
// Discretizes message lengths into fixed-tier blocks to prevent eavesdroppers
// from inferring message content from ciphertext packet lengths.

function padPlaintext(plaintext: string): Uint8Array {
  const enc = new TextEncoder().encode(plaintext);
  const len = enc.length;
  let targetSize = 128;
  const needed = len + 4;
  const tiers = [128, 256, 512, 1024, 2048, 4096];
  for (const t of tiers) {
    if (needed <= t) {
      targetSize = t;
      break;
    }
  }
  if (needed > 4096) {
    targetSize = Math.ceil(needed / 1024) * 1024;
  }

  const padded = new Uint8Array(targetSize);
  padded[0] = (len >> 24) & 0xff;
  padded[1] = (len >> 16) & 0xff;
  padded[2] = (len >> 8) & 0xff;
  padded[3] = len & 0xff;
  padded.set(enc, 4);

  if (targetSize > needed) {
    const padSlice = new Uint8Array(targetSize - needed);
    crypto.getRandomValues(padSlice);
    padded.set(padSlice, needed);
  }
  return padded;
}

function unpadPlaintext(decryptedBytes: Uint8Array): string {
  if (decryptedBytes.length >= 4) {
    const len =
      (decryptedBytes[0] << 24) |
      (decryptedBytes[1] << 16) |
      (decryptedBytes[2] << 8) |
      decryptedBytes[3];
    if (len >= 0 && 4 + len <= decryptedBytes.length) {
      return new TextDecoder().decode(decryptedBytes.slice(4, 4 + len));
    }
  }
  return new TextDecoder().decode(decryptedBytes);
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
  const padded = padPlaintext(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    padded as unknown as BufferSource,
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
  return unpadPlaintext(new Uint8Array(decrypted));
}

const EMOJI_FINGERPRINT_POOL = [
  "🛡️", "⚡", "🔒", "🔑", "🛰️", "🛸", "💎", "🔮",
  "🧬", "🌌", "⚓", "⚔️", "👁️", "🎯", "🔥", "🪐",
];

async function computeVisualEmojiHash(safetyNumber: string): Promise<string> {
  const enc = new TextEncoder().encode(safetyNumber);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  const bytes = new Uint8Array(digest);
  const emojis: string[] = [];
  for (let i = 0; i < 4; i++) {
    const idx = (bytes[i] ^ bytes[i + 4]) % EMOJI_FINGERPRINT_POOL.length;
    emojis.push(EMOJI_FINGERPRINT_POOL[idx]);
  }
  return emojis.join("  ");
}

async function generateTerminalQr(
  safetyNumber: string,
  user1: string,
  user2: string,
): Promise<string> {
  try {
    const peers = [user1.toLowerCase(), user2.toLowerCase()].sort().join(",");
    const payload = `sentinel://verify?peers=${peers}&sn=${safetyNumber.replace(/\s+/g, "")}`;
    return await QRCode.toString(payload, { type: "terminal", small: true });
  } catch {
    return "";
  }
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

// ─── Native Anti-Screen Capture (Windows Display Affinity) ───────────────────

async function setScreenProtection(enabled: boolean): Promise<boolean> {
  try {
    const tauri = typeof window !== "undefined" && (window as any).__TAURI__;
    if (tauri && tauri.core && tauri.core.invoke) {
      return await tauri.core.invoke("set_screen_protection", { enabled });
    }
  } catch (e) {
    console.warn("Screen protection not supported or failed:", e);
  }
  return false;
}

// ─── Cryptographic Memory Scrubbing & Zeroization ────────────────────────────

function zeroizeBuffer(buf: ArrayBuffer | Uint8Array | null | undefined) {
  if (!buf) return;
  try {
    const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    crypto.getRandomValues(view);
    view.fill(0);
  } catch {}
}

// ─── Trust-On-First-Use (TOFU) & MITM Detection ──────────────────────────────

type TofuStatus = "trusted" | "verified" | "mismatch";

type TofuRecord = {
  peer: string;
  identityKey: string;
  fingerprint: string;
  visualHash: string;
  firstSeen: string;
  status: TofuStatus;
  lastSeen: string;
};

function getTofuRecord(username: string, peer: string): TofuRecord | null {
  try {
    const raw = localStorage.getItem(`sentinel_tofu_${username}_${peer}`);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveTofuRecord(username: string, peer: string, record: TofuRecord) {
  try {
    localStorage.setItem(`sentinel_tofu_${username}_${peer}`, JSON.stringify(record));
  } catch {}
}

async function checkTofu(
  username: string,
  peer: string,
  incomingIdentityKey: string,
  myIdentityKey: string,
): Promise<{ status: TofuStatus; record: TofuRecord; isNew: boolean }> {
  const existing = getTofuRecord(username, peer);
  const fingerprint = await computeSafetyNumber(myIdentityKey, incomingIdentityKey);
  const visualHash = await computeVisualEmojiHash(fingerprint);

  if (!existing) {
    const record: TofuRecord = {
      peer,
      identityKey: incomingIdentityKey,
      fingerprint,
      visualHash,
      firstSeen: new Date().toISOString(),
      status: "trusted",
      lastSeen: new Date().toISOString(),
    };
    saveTofuRecord(username, peer, record);
    return { status: "trusted", record, isNew: true };
  }

  if (existing.identityKey !== incomingIdentityKey) {
    existing.status = "mismatch";
    existing.lastSeen = new Date().toISOString();
    saveTofuRecord(username, peer, existing);
    return { status: "mismatch", record: existing, isNew: false };
  }

  existing.lastSeen = new Date().toISOString();
  saveTofuRecord(username, peer, existing);
  return { status: existing.status, record: existing, isNew: false };
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

function zeroizeRatchetState(state: RatchetState | null) {
  if (!state) return;
  zeroizeBuffer(state.rootKey);
  if (state.sendingChainKey) zeroizeBuffer(state.sendingChainKey);
  if (state.receivingChainKey) zeroizeBuffer(state.receivingChainKey);
}

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
  const [screenShield, setScreenShield] = useState<boolean>(true);
  const [isLocked, setIsLocked] = useState<boolean>(false);
  const [autoLockMinutes, setAutoLockMinutes] = useState<number>(5);
  const [unlockInput, setUnlockInput] = useState<string>("");
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [cloudStatus, setCloudStatus] = useState<{
    configured: boolean;
    source: string;
    projectId?: string;
  }>({ configured: false, source: "none" });
  const [serverConfig, setServerConfig] = useState<ServerConfig>(() =>
    getActiveServerConfig(),
  );

  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const usernameRef = useRef<string | null>(null);
  const activePeerRef = useRef<string | null>(null);
  const serverConfigRef = useRef<ServerConfig>(serverConfig);
  serverConfigRef.current = serverConfig;

  const getApiBase = useCallback(() => serverConfigRef.current.apiUrl, []);
  const getWsUrl = useCallback(() => serverConfigRef.current.wsUrl, []);
  const privateKeyRef = useRef<CryptoKey | null>(null);
  const myPublicKeyB64Ref = useRef<string | null>(null);
  const spkPrivateRef = useRef<CryptoKey | null>(null);
  const opksRef = useRef<{ pub: string; priv: string }[]>([]);
  const safetyNumberRef = useRef<string | null>(null);
  const ratchetRef = useRef<RatchetState | null>(null);
  const ratchetsByPeerRef = useRef<Map<string, RatchetState>>(new Map());
  const disappearTimersRef = useRef<Map<string, number>>(new Map());
  const vaultKeyRef = useRef<CryptoKey | null>(null);
  const seenMessagesRef = useRef<Set<string>>(new Set());
  const isReplenishingRef = useRef<boolean>(false);
  const tofuMismatchesRef = useRef<Set<string>>(new Set());
  const lastUserActivityRef = useRef<number>(Date.now());

  const pendingCiphertextsRef = useRef<
    Map<string, { id: string; header: any; body: string; from: string }[]>
  >(new Map());

  useEffect(() => {
    usernameRef.current = username;
  }, [username]);

  useEffect(() => {
    activePeerRef.current = activePeer;
  }, [activePeer]);

  const zeroizeAllKeys = useCallback(() => {
    if (ratchetRef.current) zeroizeRatchetState(ratchetRef.current);
    ratchetsByPeerRef.current.forEach((r) => zeroizeRatchetState(r));
    ratchetsByPeerRef.current.clear();
    ratchetRef.current = null;

    privateKeyRef.current = null;
    spkPrivateRef.current = null;
    opksRef.current.forEach((opk) => {
      opk.priv = "";
    });
    opksRef.current = [];
    vaultKeyRef.current = null;
    safetyNumberRef.current = null;
  }, []);

  const executePanic = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
      wsRef.current = null;
    }

    disappearTimersRef.current.forEach((t) => window.clearTimeout(t));
    disappearTimersRef.current.clear();

    seenMessagesRef.current.clear();
    isReplenishingRef.current = false;
    zeroizeAllKeys();
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
        isCmdResult: true,
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "🚨 EMERGENCY PANIC PURGE EXECUTED 🚨",
        timestamp: new Date(),
        isCmdResult: true,
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "• In-memory private keys, ratchets & vault key purged",
        timestamp: new Date(),
        isCmdResult: true,
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "• Local storage shredded and overwritten",
        timestamp: new Date(),
        isCmdResult: true,
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "• WebSocket connection forcefully severed",
        timestamp: new Date(),
        isCmdResult: true,
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "════════════════════════════════════════════════════════════════════",
        timestamp: new Date(),
        isCmdResult: true,
      },
      {
        id: crypto.randomUUID(),
        type: "system",
        text: "Identity erased from this client. Use /register <user> to establish a new identity.",
        timestamp: new Date(),
        isCmdResult: true,
      },
    ]);
  }, []);

  const logBackground = useCallback((text: string, details?: unknown) => {
    if (details !== undefined) {
      console.log(`[Sentinel System] ${text}`, details);
    } else {
      console.log(`[Sentinel System] ${text}`);
    }
  }, []);

  const addCommandResult = useCallback((text: string, peer?: string) => {
    const targetPeer =
      peer !== undefined ? peer : (activePeerRef.current ?? undefined);
    setMessages((prev) => [
      ...prev,
      {
        id: crypto.randomUUID(),
        type: "system",
        text,
        timestamp: new Date(),
        peer: targetPeer,
        isCmdResult: true,
      },
    ]);
  }, []);

  const lockSession = useCallback(
    (reason: string = "Manual lock") => {
      if (!usernameRef.current) return;
      zeroizeAllKeys();
      setIsLocked(true);
      setUnlockError(null);
      setUnlockInput("");
      logBackground(`Session locked: ${reason}. In-memory keys scrubbed.`);
    },
    [zeroizeAllKeys, logBackground],
  );

  useEffect(() => {
    const handleGlobalKey = (e: globalThis.KeyboardEvent) => {
      if (
        (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "x") ||
        (e.ctrlKey && e.altKey && e.key.toLowerCase() === "p")
      ) {
        e.preventDefault();
        executePanic();
      } else if (e.ctrlKey && e.key.toLowerCase() === "l") {
        e.preventDefault();
        lockSession("Hotkey Ctrl+L");
      }
    };

    const updateActivity = () => {
      lastUserActivityRef.current = Date.now();
    };

    window.addEventListener("keydown", handleGlobalKey);
    window.addEventListener("keydown", updateActivity);
    window.addEventListener("mousedown", updateActivity);
    window.addEventListener("mousemove", updateActivity);

    const autoLockInterval = window.setInterval(() => {
      if (!usernameRef.current || isLocked || autoLockMinutes <= 0) return;
      const idleTime = Date.now() - lastUserActivityRef.current;
      if (idleTime > autoLockMinutes * 60 * 1000) {
        lockSession(`Inactivity timeout (${autoLockMinutes}m)`);
      }
    }, 5000);

    return () => {
      window.removeEventListener("keydown", handleGlobalKey);
      window.removeEventListener("keydown", updateActivity);
      window.removeEventListener("mousedown", updateActivity);
      window.removeEventListener("mousemove", updateActivity);
      window.clearInterval(autoLockInterval);
    };
  }, [executePanic, lockSession, isLocked, autoLockMinutes]);

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

  const unlockSession = useCallback(
    async (passphrase?: string) => {
      const currentName = usernameRef.current;
      if (!currentName) {
        setIsLocked(false);
        return true;
      }

      if (hasVaultConfigured(currentName)) {
        if (!passphrase) {
          setUnlockError("Vault passphrase required to unlock.");
          return false;
        }
        const vKey = await unlockVault(currentName, passphrase);
        if (!vKey) {
          setUnlockError("Incorrect passphrase. Decryption failed.");
          return false;
        }
        vaultKeyRef.current = vKey;
        setVaultStatus("unlocked");

        const privB64 = await loadPrivateKey(currentName, vKey);
        if (privB64) {
          privateKeyRef.current = await importPrivateKey(privB64);
          setHasKeys(true);
        }
        const spkPrivB64 = await loadSpkPrivate(currentName, vKey);
        if (spkPrivB64) {
          spkPrivateRef.current = await importPrivateKey(spkPrivB64);
        }
        const savedOpks = await loadOpks(currentName, vKey);
        opksRef.current = savedOpks;
      }

      if (activePeerRef.current) {
        const p = activePeerRef.current;
        const loaded = await loadSession(currentName, p, vaultKeyRef.current);
        if (loaded) {
          ratchetRef.current = loaded;
          ratchetsByPeerRef.current.set(p, loaded);
        }
      }

      setIsLocked(false);
      setUnlockError(null);
      setUnlockInput("");
      lastUserActivityRef.current = Date.now();
      addCommandResult(
        "✓ Session unlocked. In-memory keys restored.",
        activePeerRef.current ?? undefined,
      );
      return true;
    },
    [addCommandResult],
  );

  const addMessage = useCallback(
    (
      type: Message["type"],
      text: string,
      peer?: string,
      isCmdResult?: boolean,
    ) => {
      setMessages((prev) => {
        const targetPeer =
          peer !== undefined ? peer : (activePeerRef.current ?? undefined);

        const next = [
          ...prev,
          {
            id: crypto.randomUUID(),
            type,
            text,
            timestamp: new Date(),
            peer: targetPeer,
            isCmdResult: type === "command" || isCmdResult === true,
          },
        ];
        const p = targetPeer;
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

  const checkHealth = useCallback(async (customApiUrl?: string) => {
    try {
      const base = customApiUrl || serverConfigRef.current.apiUrl;
      const res = await fetch(`${base}/health`);
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

  const replenishPrekeys = useCallback(
    async (minThreshold = 5, batchSize = 15) => {
      const currentName = usernameRef.current;
      if (!currentName || !privateKeyRef.current || isReplenishingRef.current) return;

      try {
        isReplenishingRef.current = true;
        const res = await fetch(`${getApiBase()}/api/prekeys-count/${currentName}`);
        if (!res.ok) return;
        const data = await res.json();
        if (!data.success) return;

        if (data.count < minThreshold) {
          addMessage(
            "system",
            `[Security] OPK prekey pool low (${data.count} left). Generating ${batchSize} fresh one-time prekeys...`,
          );

          const newOpks: { pub: string; priv: string }[] = [];
          for (let i = 0; i < batchSize; i++) {
            const kp = await generateKeyPair();
            newOpks.push({
              pub: await exportPublicKey(kp.publicKey),
              priv: await exportPrivateKey(kp.privateKey),
            });
          }

          const existingOpks = await loadOpks(currentName, vaultKeyRef.current);
          const merged = [...existingOpks, ...newOpks];
          await saveOpks(currentName, merged, vaultKeyRef.current);
          opksRef.current = merged;

          const appendRes = await fetch(`${getApiBase()}/api/prekeys/append`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: currentName,
              one_time_prekeys: newOpks.map((o) => o.pub),
            }),
          });
          const appendData = await appendRes.json();
          if (appendData.success) {
            addMessage(
              "system",
              `[Security] Continuous forward secrecy renewed. Active OPK pool: ${data.count + batchSize}.`,
            );
          }
        }
      } catch (err) {
        console.warn("Prekey auto-replenish skipped:", err);
      } finally {
        isReplenishingRef.current = false;
      }
    },
    [addMessage],
  );

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
                    text: plaintext,
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
      const existingHistoryIds = new Set(history.map((h) => h.id));
      const inMemoryNonHistory = prev.filter(
        (m) => m.peer === peer && !existingHistoryIds.has(m.id),
      );
      const otherMessages = prev.filter((m) => m.peer !== peer);
      return [...otherMessages, ...history, ...inMemoryNonHistory];
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

  const connectWs = useCallback((customWsUrl?: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const targetWs = customWsUrl || serverConfigRef.current.wsUrl;
      const ws = new WebSocket(targetWs);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnStatus("online");
        addMessage("system", `Connected to Sentinel relay (${targetWs})`);
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

                // Replay Protection: Drop duplicate packets
                const packetFingerprint = `${from}:${header.dh || "0"}:${header.n}`;
                if (seenMessagesRef.current.has(packetFingerprint)) {
                  addMessage(
                    "system",
                    `⚠️ [Security Alert] Dropped duplicate / replayed packet (n=${header.n}) from ${from}.`,
                    from,
                  );
                  break;
                }
                seenMessagesRef.current.add(packetFingerprint);
                if (seenMessagesRef.current.size > 2000) {
                  const firstKey = seenMessagesRef.current.keys().next().value;
                  if (firstKey) seenMessagesRef.current.delete(firstKey);
                }

                if (header?.x3dh) {
                  if (!header.x3dh.ik) {
                    addMessage(
                      "peer",
                      "(encrypted – missing identity key)",
                      from,
                    );
                    break;
                  }

                  if (usernameRef.current && myPublicKeyB64Ref.current) {
                    const tofu = await checkTofu(
                      usernameRef.current,
                      from,
                      header.x3dh.ik,
                      myPublicKeyB64Ref.current,
                    );
                    if (tofu.status === "mismatch") {
                      tofuMismatchesRef.current.add(from);
                      addMessage(
                        "system",
                        `🚨 [MITM Alert] Remote identity key for '${from}' does not match previously trusted key! Potential interception detected. Type /trust ${from} if verified.`,
                        from,
                      );
                    }
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
                    void replenishPrekeys();
                  }
                }

                if (!state) {
                  const id = crypto.randomUUID();
                  const placeholder = `(encrypted – open chat or /new ${from})`;
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
                    "(no receiving chain yet)",
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
                    "(message number mismatch)",
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
                      text: plaintext,
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
                logBackground(`Couldn't decrypt incoming packet from ${msg.from}:`, err);
                addMessage(
                  "peer",
                  `Couldn’t decrypt this message. Run /reset ${msg.from} then /new ${msg.from} to start a fresh secure chat.`,
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
    void setScreenProtection(true);
    setCloudStatus(getFirebaseStatus());
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
      const cfg = getActiveServerConfig();
      const ok = await checkHealth(cfg.apiUrl);
      if (ok) {
        addMessage(
          "system",
          `Relay online — ${cfg.apiUrl} [${cfg.source.toUpperCase()}]`,
        );
        connectWs(cfg.wsUrl);
      } else {
        addMessage(
          "system",
          `Relay offline (${cfg.apiUrl}). Start backend with: cd backend && cargo run  (or switch relay: /server <url>)`,
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

  useEffect(() => {
    if (!username || !hasKeys) return;
    void replenishPrekeys();
    const interval = setInterval(() => {
      void replenishPrekeys();
    }, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, [username, hasKeys, replenishPrekeys]);

  const getCleanMessageText = (msg: Message) => {
    if (msg.type === "peer") {
      const peerName = msg.peer || activePeer;
      if (peerName) {
        const prefix = `[${peerName}]`;
        if (msg.text.startsWith(prefix)) {
          return msg.text.slice(prefix.length).trimStart();
        }
      }
      const match = msg.text.match(/^\[[a-zA-Z0-9_\-\.]+\]\s*(.*)$/);
      if (match) {
        return match[1];
      }
    }
    return msg.text;
  };

  const displayedMessages = messages.filter((m) => {
    if (m.type === "system" && !m.isCmdResult) {
      return false;
    }
    if (!activePeer) {
      return m.type === "command" || m.isCmdResult;
    }
    if (m.peer === activePeer) return true;
    if (!m.peer && (m.type === "command" || m.isCmdResult)) return true;
    return false;
  });

  // ─── Commands ─────────────────────────────────────────────────────────────

  const handleCommand = async (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    if (trimmed.startsWith("/")) {
      addMessage("command", trimmed, activePeer ?? undefined);
    }

    const parts = trimmed.split(/\s+/);
    const command = parts[0].toLowerCase();

    switch (command) {
      case "/help":
        addCommandResult(
          `Available commands:
  /help                  Show this help
  /register <username>   Create identity + prekeys
  /login <username>      Login and load keys + history
  /new <user>            Start or restore session with user
  /chats                 List contacts / sessions
  /verify                Show Safety Number & TOFU verification status
  /trust [user]          Explicitly trust remote Identity Key after rotation
  /shield [on|off]       Toggle Anti-Screen Capture / OBS defense (Win32)
  /lock [mins|off]       Lock terminal immediately (or set auto-lock timer)
  /unlock <passphrase>   Unlock terminal & decrypt in-memory keys
  /disappear <time|off>  Auto-delete msgs (30s, 5m, 1h, off)
  /reset <user>          Reset broken secure session with user
  /clear                 Clear current chat history view
  /status                Show status & security parameters
  /server [url|reset]    View, configure, or reset relay server URL
  /cloud-backup <pass>   Backup E2EE vault to Firebase (Zero-Knowledge)
  /cloud-restore <u p>   Restore identity & sessions from Firebase on any device
  /cloud-config [json]   Configure or view Firebase credentials
  /export-key            Export armored private keys for other devices
  /import-key <key>      Import private keys on this browser
  /logout                End session
  /panic                 Purge memory & shred local storage (Ctrl+Shift+X)

  Hotkeys: Ctrl+L (Lock) | Ctrl+Shift+X (Panic Shred)`,
          activePeer ?? undefined,
        );
        break;

      case "/chats": {
        if (contacts.length === 0) {
          addCommandResult("No contacts yet. Use /new <user> to start.", activePeer ?? undefined);
        } else {
          addCommandResult(
            `Contacts:\n${contacts
              .map((c) => (c === activePeer ? `  → ${c} (active)` : `    ${c}`))
              .join("\n")}`,
            activePeer ?? undefined,
          );
        }
        break;
      }

      case "/disappear": {
        if (!activePeer || !username) {
          addCommandResult("Open a chat first, then use /disappear <time>", activePeer ?? undefined);
          break;
        }
        if (!parts[1] || parts[1].toLowerCase() === "off") {
          setDisappearMs(null);
          saveDisappearMs(username, activePeer, null);
          addCommandResult(`Disappearing messages OFF for ${activePeer}.`, activePeer);
          break;
        }
        const ms = parseDuration(parts[1]);
        if (ms === null) {
          addCommandResult(
            "Usage: /disappear <time>  e.g. 30s, 5m, 1h  |  /disappear off",
            activePeer,
          );
          break;
        }
        setDisappearMs(ms);
        saveDisappearMs(username, activePeer, ms);
        addCommandResult(
          `Disappearing messages ON for ${activePeer}: ${formatDuration(ms)}`,
          activePeer,
        );
        break;
      }

      case "/reset": {
        if (!username) {
          addCommandResult("Login first.", activePeer ?? undefined);
          break;
        }
        const peer = (parts[1] || activePeer || "").toLowerCase();
        if (!peer) {
          addCommandResult("Usage: /reset <username>", activePeer ?? undefined);
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

        addCommandResult(
          `Secure session with ${peer} was reset on this device. Run /new ${peer} to establish a fresh session.`,
          activePeer ?? undefined,
        );
        break;
      }

      case "/register": {
        if (!parts[1]) {
          addCommandResult("Usage: /register <username>", activePeer ?? undefined);
          break;
        }
        const name = parts[1].toLowerCase();
        logBackground(`Registering "${name}"...`);

        try {
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

          const res = await fetch(`${getApiBase()}/api/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: name,
              public_key: publicKeyB64,
            }),
          });
          const data = await res.json();

          if (!data.success) {
            addCommandResult(`Registration error: ${data.message}`, activePeer ?? undefined);
            break;
          }

          const preRes = await fetch(`${getApiBase()}/api/prekeys`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: name,
              signed_prekey: spkPub,
              one_time_prekeys: opks.map((o) => o.pub),
            }),
          });
          await preRes.json();

          setUsername(data.user.username);
          const saved = listSavedPeers(data.user.username);
          if (saved.length > 0) {
            setContacts(saved);
          }

          sendWs({ type: "auth", username: data.user.username });
          setUsersCount((c) => c + 1);
          addCommandResult(`Registered identity "${data.user.username}". E2EE prekeys ready.`, activePeer ?? undefined);
        } catch (err) {
          console.error(err);
          addCommandResult("Failed to register. Is the backend running?", activePeer ?? undefined);
          setConnStatus("offline");
        }
        break;
      }

      case "/login": {
        if (!parts[1]) {
          addCommandResult("Usage: /login <username>", activePeer ?? undefined);
          break;
        }
        const name = parts[1].toLowerCase();
        logBackground(`Logging in as "${name}"...`);

        try {
          const res = await fetch(`${getApiBase()}/api/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: name }),
          });
          const data = await res.json();

          if (!data.success) {
            addCommandResult(`Login error: ${data.message}`, activePeer ?? undefined);
            break;
          }

          const privB64 = await loadPrivateKey(name, vaultKeyRef.current);
          if (!privB64) {
            setUsername(data.user.username);
            if (data.user.public_key)
              myPublicKeyB64Ref.current = data.user.public_key;
            sendWs({ type: "auth", username: data.user.username });

            const hasCloudVault = await checkCloudVaultExists(name);
            if (hasCloudVault) {
              addCommandResult(
                `☁️ ZERO-KNOWLEDGE CLOUD VAULT DETECTED FOR '${data.user.username}'!\n` +
                `────────────────────────────────────────────────────────────\n` +
                `Your encrypted keys are backed up in Firebase.\n` +
                `To restore your full identity, prekeys & chats on this device, run:\n\n` +
                `   /cloud-restore ${data.user.username} <your_passphrase>`,
                activePeer ?? undefined,
              );
            } else {
              addCommandResult(
                `⚠️ Logged in as '${data.user.username}', but NO PRIVATE KEY exists on this device/browser.\n` +
                `────────────────────────────────────────────────────────────\n` +
                `• Sentinel end-to-end encryption stores private keys locally on the device where you registered.\n` +
                `• If you backed up your keys, restore with: /cloud-restore ${data.user.username} <passphrase>\n` +
                `• Or re-register keys here: /register ${data.user.username} (or use /import-key).\n` +
                `• Or create a distinct testing identity: /register <another_name>`,
                activePeer ?? undefined,
              );
            }
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
          sendWs({ type: "auth", username: data.user.username });

          addCommandResult(
            `Logged in as ${data.user.username}.${saved.length > 0 ? ` Loaded ${saved.length} contact(s).` : " Use /new <peer> to start a chat."}`,
            activePeer ?? undefined,
          );
        } catch {
          addCommandResult("Failed to reach backend.", activePeer ?? undefined);
          setConnStatus("offline");
        }
        break;
      }

      case "/new": {
        if (!parts[1]) {
          addCommandResult("Usage: /new <username>", activePeer ?? undefined);
          break;
        }
        if (!username) {
          addCommandResult("Login or register first.", activePeer ?? undefined);
          break;
        }
        if (!privateKeyRef.current || !myPublicKeyB64Ref.current) {
          addCommandResult(
            `Cannot start session: No private key found for '${username}' on this device.\n` +
            `Run /register ${username} to generate keys on this browser, or /register <new_name>.`,
            activePeer ?? undefined,
          );
          break;
        }

        const peer = parts[1].toLowerCase();
        if (peer === username) {
          addCommandResult("Cannot chat with yourself.", activePeer ?? undefined);
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
          addCommandResult(`Chat opened with ${peer}. Ready to message.`, peer);
          await tryDecryptPending(peer);
          break;
        }

        logBackground(`Fetching prekey bundle for ${peer}...`);

        try {
          const res = await fetch(`${getApiBase()}/api/prekey-bundle/${peer}`);
          const bundle = await res.json();

          if (
            !bundle.success ||
            !bundle.identity_key ||
            !bundle.signed_prekey
          ) {
            addCommandResult(`No prekeys for '${peer}'. They must /register first.`, activePeer ?? undefined);
            break;
          }

          // TOFU Verification
          if (username && myPublicKeyB64Ref.current) {
            const tofu = await checkTofu(
              username,
              peer,
              bundle.identity_key,
              myPublicKeyB64Ref.current,
            );
            if (tofu.status === "mismatch") {
              tofuMismatchesRef.current.add(peer);
              addCommandResult(
                `🚨 CRITICAL SECURITY WARNING: IDENTITY KEY MISMATCH FOR '${peer}'!\n` +
                `────────────────────────────────────────────────────────────\n` +
                `STORED FINGERPRINT:   ${tofu.record.fingerprint}  [  ${tofu.record.visualHash}  ]\n` +
                `NEW INCOMING KEY:     ${await computeSafetyNumber(myPublicKeyB64Ref.current, bundle.identity_key)}\n` +
                `⚠️ The public identity key for '${peer}' has CHANGED since your previous verification.\n` +
                `• Potential active Man-in-the-Middle (MITM) attack or device reset.\n` +
                `Outgoing messaging to '${peer}' is BLOCKED.\n` +
                `Compare fingerprints with ${peer} out-of-band and run: /trust ${peer}`,
                peer,
              );
            }
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

          addCommandResult(`Secure E2EE session established with ${peer}. Ready to message. (Type /verify for Safety Number)`, peer);
          await tryDecryptPending(peer);
          void replenishPrekeys();
        } catch (err) {
          console.error(err);
          addCommandResult(`Failed to set up session with ${peer}.`, activePeer ?? undefined);
        }
        break;
      }

      case "/verify": {
        if (!activePeer || !username) {
          addCommandResult("No active chat. Use /new <user> first.", activePeer ?? undefined);
          break;
        }

        let sn = safetyNumberRef.current;
        if (!sn) {
          try {
            const res = await fetch(`${getApiBase()}/api/public-key/${activePeer}`);
            const data = await res.json();
            if (data.success && data.public_key && myPublicKeyB64Ref.current) {
              sn = await computeSafetyNumber(myPublicKeyB64Ref.current, data.public_key);
              safetyNumberRef.current = sn;
            }
          } catch {}
        }

        if (!sn) {
          addCommandResult("Unable to compute safety number. Open a chat or /new <user>.", activePeer);
          break;
        }

        const visualEmoji = await computeVisualEmojiHash(sn);
        const tofuRec = getTofuRecord(username, activePeer);
        const tofuStatus = !tofuRec
          ? "NOT CACHED"
          : tofuRec.status === "mismatch"
            ? "🚨 MISMATCH (POSSIBLE MITM / KEY ROTATION)"
            : tofuRec.status === "verified"
              ? "🛡️ MANUALLY VERIFIED"
              : "✓ TRUSTED (TRUST-ON-FIRST-USE)";

        addCommandResult(
          `🛡️ SAFETY NUMBER VERIFICATION: ${username} ⟷ ${activePeer}\n` +
          `────────────────────────────────────────────────────────────\n` +
          `TOFU STATUS:  ${tofuStatus}\n` +
          `FINGERPRINT:  ${sn}\n` +
          `VISUAL HASH:  [  ${visualEmoji}  ]\n` +
          `Compare this visual hash or fingerprint with ${activePeer} to verify channel integrity.\n` +
          `Type /trust ${activePeer} to explicitly acknowledge and trust key.`,
          activePeer,
        );
        break;
      }

      case "/trust": {
        const targetPeer = parts[1] || activePeer;
        if (!targetPeer) {
          addCommandResult("Usage: /trust <username>", activePeer ?? undefined);
          break;
        }
        if (!username) {
          addCommandResult("Login first.", activePeer ?? undefined);
          break;
        }
        tofuMismatchesRef.current.delete(targetPeer);
        try {
          const res = await fetch(`${getApiBase()}/api/public-key/${targetPeer}`);
          const data = await res.json();
          if (data.success && data.public_key && myPublicKeyB64Ref.current) {
            const sn = await computeSafetyNumber(myPublicKeyB64Ref.current, data.public_key);
            const vh = await computeVisualEmojiHash(sn);
            saveTofuRecord(username, targetPeer, {
              peer: targetPeer,
              identityKey: data.public_key,
              fingerprint: sn,
              visualHash: vh,
              firstSeen: new Date().toISOString(),
              status: "verified",
              lastSeen: new Date().toISOString(),
            });
            addCommandResult(
              `🛡️ KEY TRUST CONFIRMED: Identity Key for '${targetPeer}' explicitly trusted.\n` +
              `Safety Number: ${sn}\n` +
              `Visual Hash:   [  ${vh}  ]\n` +
              `Messaging unblocked.`,
              targetPeer,
            );
          } else {
            addCommandResult(`✓ Cleared mismatch flag for '${targetPeer}'.`, targetPeer);
          }
        } catch {
          addCommandResult(`✓ Cleared mismatch flag for '${targetPeer}'.`, targetPeer);
        }
        break;
      }

      case "/shield": {
        const arg = parts[1]?.toLowerCase();
        const nextVal = arg === "on" ? true : arg === "off" ? false : !screenShield;
        setScreenShield(nextVal);
        void setScreenProtection(nextVal);
        addCommandResult(
          nextVal
            ? "🛡️ Screen Protection ENABLED. Window display affinity is active (hidden from screen capture, OBS & screen share)."
            : "⚠️ Screen Protection DISABLED. Window is visible to capture tools.",
          activePeer ?? undefined,
        );
        break;
      }

      case "/lock": {
        const arg = parts[1]?.toLowerCase();
        if (arg === "off") {
          setAutoLockMinutes(0);
          addCommandResult("Auto-lock timer DISABLED.", activePeer ?? undefined);
        } else if (arg && !isNaN(Number(arg))) {
          const mins = Math.max(1, Number(arg));
          setAutoLockMinutes(mins);
          addCommandResult(`Auto-lock timer set to ${mins} minute(s).`, activePeer ?? undefined);
        } else {
          lockSession("Manual lock command");
        }
        break;
      }

      case "/unlock": {
        const pass = parts.slice(1).join(" ");
        await unlockSession(pass || undefined);
        break;
      }

      case "/server": {
        if (!parts[1]) {
          const cfg = getActiveServerConfig();
          const t0 = performance.now();
          let pingStr = "testing...";
          try {
            const res = await fetch(`${cfg.apiUrl}/health`, { signal: AbortSignal.timeout(3000) });
            const lat = Math.round(performance.now() - t0);
            if (res.ok) {
              const data = await res.json();
              pingStr = `ONLINE (${lat}ms latency | ${data.users_online ?? 0} online / ${data.users_registered ?? 0} registered)`;
            } else {
              pingStr = `HTTP ${res.status}`;
            }
          } catch (e: any) {
            pingStr = `OFFLINE / UNREACHABLE (${e?.message || "connection error"})`;
          }

          addCommandResult(
            `🌐 SENTINEL RELAY CONFIGURATION:\n` +
            `────────────────────────────────────────────────────────────\n` +
            `API ENDPOINT:   ${cfg.apiUrl}\n` +
            `WEBSOCKET:      ${cfg.wsUrl}\n` +
            `CONFIG SOURCE:  ${cfg.source.toUpperCase()} (${cfg.source === "runtime" ? "Custom override in localStorage" : cfg.source === "env" ? "Environment variable" : "Default fallback"})\n` +
            `STATUS:         ${pingStr}\n\n` +
            `Usage:\n` +
            `  /server <url>    Point to a remote relay server (e.g. /server https://relay.example.com)\n` +
            `  /server reset    Reset to environment default`,
            activePeer ?? undefined,
          );
          break;
        }

        if (parts[1].toLowerCase() === "reset") {
          clearRuntimeServerConfig();
          const def = getActiveServerConfig();
          setServerConfig(def);
          serverConfigRef.current = def;

          if (wsRef.current) {
            wsRef.current.close();
            wsRef.current = null;
          }
          setWsAuthed(false);

          addCommandResult(
            `Relay configuration reset to: ${def.apiUrl} [${def.source.toUpperCase()}]. Reconnecting...`,
            activePeer ?? undefined,
          );

          const ok = await checkHealth(def.apiUrl);
          if (ok) {
            connectWs(def.wsUrl);
          }
          break;
        }

        const inputUrl = parts[1];
        const res = saveRuntimeServerConfig(inputUrl);
        if (!res.success) {
          addCommandResult(`Error setting relay server: ${res.error}`, activePeer ?? undefined);
          break;
        }

        const newCfg: ServerConfig = {
          apiUrl: res.apiUrl,
          wsUrl: res.wsUrl,
          source: "runtime",
        };
        setServerConfig(newCfg);
        serverConfigRef.current = newCfg;

        if (wsRef.current) {
          wsRef.current.close();
          wsRef.current = null;
        }
        setWsAuthed(false);

        addCommandResult(
          `✓ Relay server updated to:\n  API: ${newCfg.apiUrl}\n  WS:  ${newCfg.wsUrl}\nSaved in localStorage. Testing connection...`,
          activePeer ?? undefined,
        );

        const ok = await checkHealth(newCfg.apiUrl);
        if (ok) {
          addCommandResult(`✓ Connected to new relay server!`, activePeer ?? undefined);
          connectWs(newCfg.wsUrl);
        } else {
          addCommandResult(`⚠️ Server saved, but health check failed at ${newCfg.apiUrl}. Check that the relay is running and reachable.`, activePeer ?? undefined);
        }
        break;
      }

      case "/status":
        addCommandResult(
          `Status:
  User:            ${username || "not registered"}
  Active chat:     ${activePeer || "none"}
  Contacts:        ${contacts.length}
  Backend:         ${connStatus.toUpperCase()} (${serverConfigRef.current.apiUrl} [${serverConfigRef.current.source.toUpperCase()}])
  Screen Shield:   ${screenShield ? "ACTIVE (Anti-Screen Capture)" : "DISABLED"}
  Auto-Lock:       ${autoLockMinutes > 0 ? `${autoLockMinutes} min inactivity` : "OFF"}
  Encryption:      X3DH + Double Ratchet (AES-256-GCM)
  Disappear:       ${disappearMs ? formatDuration(disappearMs) : "off"}
  WebSocket:       ${
    wsRef.current?.readyState === WebSocket.OPEN ? "connected" : "disconnected"
  }`,
          activePeer ?? undefined,
        );
        break;

      case "/clear":
        if (activePeer && username) {
          clearChatHistory(username, activePeer);
          setMessages((prev) =>
            prev.filter((m) => m.peer !== activePeer),
          );
          addCommandResult(`Cleared chat history with ${activePeer}.`, activePeer);
        } else {
          addCommandResult("No active chat to clear.", activePeer ?? undefined);
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
        zeroizeAllKeys();
        addCommandResult("Logged out.", undefined);
        break;

      case "/panic":
        executePanic();
        break;

      case "/cloud-backup":
      case "/backup": {
        if (!username || !privateKeyRef.current) {
          addCommandResult("You must be registered or logged in to backup keys.", activePeer ?? undefined);
          break;
        }
        const passphrase = parts.slice(1).join(" ").trim();
        if (!passphrase) {
          addCommandResult("Usage: /cloud-backup <master_passphrase>", activePeer ?? undefined);
          break;
        }
        if (passphrase.length < 6) {
          addCommandResult("Passphrase must be at least 6 characters for cloud vault security.", activePeer ?? undefined);
          break;
        }

        addCommandResult("☁️ Encrypting local keys and session ratchets with PBKDF2 (600,000 iterations) + AES-256-GCM...", activePeer ?? undefined);

        try {
          const privB64 = await exportPrivateKey(privateKeyRef.current);
          const spkB64 = spkPrivateRef.current ? await exportPrivateKey(spkPrivateRef.current) : null;

          const ratchetsSnapshot: Record<string, any> = {};
          for (const peer of contacts) {
            const rawSession = localStorage.getItem(sessionStorageKey(username, peer));
            if (rawSession) {
              try { ratchetsSnapshot[peer] = JSON.parse(rawSession); } catch {}
            }
          }

          const payload: CloudVaultPayload = {
            username,
            privateKeyB64: privB64,
            spkPrivateB64: spkB64,
            opks: opksRef.current,
            contacts,
            ratchets: ratchetsSnapshot,
            exportedAt: new Date().toISOString(),
          };

          const res = await uploadZeroKnowledgeVault(username, passphrase, payload);
          if (res.success) {
            addCommandResult(
              `☁️ ZERO-KNOWLEDGE CLOUD VAULT BACKUP COMPLETE!\n` +
              `────────────────────────────────────────────────────────────\n` +
              `Identity:       ${username}\n` +
              `Contacts:       ${contacts.length} synced\n` +
              `Encryption:     Client-side AES-256-GCM (Zero-Knowledge)\n` +
              `Firebase:       Uploaded to Firestore encrypted_vaults/${username}\n\n` +
              `You can now login from ANY device/browser by running:\n` +
              `   /cloud-restore ${username} <passphrase>`,
              activePeer ?? undefined,
            );
          } else {
            addCommandResult(`❌ Cloud backup failed: ${res.message}`, activePeer ?? undefined);
          }
        } catch (err: any) {
          addCommandResult(`❌ Backup error: ${err?.message || String(err)}`, activePeer ?? undefined);
        }
        break;
      }

      case "/cloud-restore":
      case "/restore": {
        const targetUser = parts[1]?.toLowerCase();
        const passphrase = parts.slice(2).join(" ").trim();
        if (!targetUser || !passphrase) {
          addCommandResult("Usage: /cloud-restore <username> <master_passphrase>", activePeer ?? undefined);
          break;
        }

        addCommandResult(`☁️ Fetching Zero-Knowledge Cloud Vault for '${targetUser}' from Firebase...`, activePeer ?? undefined);

        try {
          const res = await downloadZeroKnowledgeVault(targetUser, passphrase);
          if (!res.success || !res.data) {
            addCommandResult(`❌ Cloud restore failed: ${res.message}`, activePeer ?? undefined);
            break;
          }

          const vault = res.data;
          await savePrivateKey(targetUser, vault.privateKeyB64, vaultKeyRef.current);
          privateKeyRef.current = await importPrivateKey(vault.privateKeyB64);

          if (vault.spkPrivateB64) {
            await saveSpkPrivate(targetUser, vault.spkPrivateB64, vaultKeyRef.current);
            spkPrivateRef.current = await importPrivateKey(vault.spkPrivateB64);
          }

          if (Array.isArray(vault.opks)) {
            await saveOpks(targetUser, vault.opks, vaultKeyRef.current);
            opksRef.current = vault.opks;
          }

          if (Array.isArray(vault.contacts)) {
            setContacts(vault.contacts);
          }

          if (vault.ratchets && typeof vault.ratchets === "object") {
            for (const [peer, rData] of Object.entries(vault.ratchets)) {
              localStorage.setItem(sessionStorageKey(targetUser, peer), JSON.stringify(rData));
            }
          }

          setUsername(targetUser);
          setHasKeys(true);
          sendWs({ type: "auth", username: targetUser });

          addCommandResult(
            `☁️ ZERO-KNOWLEDGE CLOUD VAULT RESTORED SUCCESSFULLY!\n` +
            `────────────────────────────────────────────────────────────\n` +
            `Identity:       ${targetUser}\n` +
            `Private Key:    Decrypted & loaded into device storage\n` +
            `Prekeys:        Restored (${vault.opks?.length || 0} OPKs)\n` +
            `Contacts:       ${vault.contacts?.length || 0} contact(s) restored\n\n` +
            `✓ WebSocket authenticated. Ready to chat securely from this device!`,
            activePeer ?? undefined,
          );
        } catch (err: any) {
          addCommandResult(`❌ Cloud restore error: ${err?.message || String(err)}`, activePeer ?? undefined);
        }
        break;
      }

      case "/cloud-config": {
        const rawArg = parts.slice(1).join(" ").trim();
        if (!rawArg) {
          const st = getFirebaseStatus();
          addCommandResult(
            `☁️ FIREBASE CLOUD CONFIG STATUS:\n` +
            `────────────────────────────────────────────────────────────\n` +
            `Status:     ${st.configured ? "CONFIGURED (" + st.source.toUpperCase() + ")" : "NOT CONFIGURED"}\n` +
            `Project ID: ${st.projectId || "None"}\n\n` +
            `To configure Firebase, either:\n` +
            `1. Put your credentials in .env.local (see .env.local.example)\n` +
            `2. Or paste your Firebase config JSON here:\n` +
            `   /cloud-config {"apiKey":"...","projectId":"..."}\n` +
            `3. Run '/cloud-config clear' to remove runtime config.`,
            activePeer ?? undefined,
          );
          break;
        }

        if (rawArg.toLowerCase() === "clear") {
          clearRuntimeFirebaseConfig();
          setCloudStatus(getFirebaseStatus());
          addCommandResult("✓ Cleared runtime Firebase configuration.", activePeer ?? undefined);
          break;
        }

        try {
          const parsed = JSON.parse(rawArg);
          if (!parsed.apiKey || !parsed.projectId) {
            addCommandResult("Invalid config JSON. Must contain at least 'apiKey' and 'projectId'.", activePeer ?? undefined);
            break;
          }
          saveRuntimeFirebaseConfig(parsed);
          const st = getFirebaseStatus();
          setCloudStatus(st);
          addCommandResult(
            `✓ Firebase configuration saved! Connected to project: ${st.projectId}\n` +
            `You can now use /cloud-backup <passphrase> and /cloud-restore <user> <passphrase>.`,
            activePeer ?? undefined,
          );
        } catch {
          addCommandResult("Failed to parse JSON. Please pass valid JSON: /cloud-config {\"apiKey\":\"...\",\"projectId\":\"...\"}", activePeer ?? undefined);
        }
        break;
      }

      case "/export-key": {
        if (!username || !privateKeyRef.current) {
          addCommandResult("No keys loaded to export.", activePeer ?? undefined);
          break;
        }
        const privB64 = await exportPrivateKey(privateKeyRef.current);
        const spkB64 = spkPrivateRef.current ? await exportPrivateKey(spkPrivateRef.current) : null;
        const backupObj = {
          user: username,
          priv: privB64,
          spk: spkB64,
          opks: opksRef.current,
        };
        const exportB64 = btoa(JSON.stringify(backupObj));
        addCommandResult(
          `🔑 IDENTITY KEY EXPORT FOR '${username}':\n` +
          `Copy this string and use /import-key <string> in your other browser/device:\n\n` +
          `${exportB64}\n\n` +
          `⚠️ Keep this confidential! Anyone with this key can decrypt your messages.`,
          activePeer ?? undefined,
        );
        break;
      }

      case "/import-key": {
        if (!parts[1]) {
          addCommandResult("Usage: /import-key <exported_key_string>", activePeer ?? undefined);
          break;
        }
        try {
          const raw = atob(parts[1]);
          const parsed = JSON.parse(raw);
          if (!parsed.user || !parsed.priv) {
            addCommandResult("Invalid key export payload.", activePeer ?? undefined);
            break;
          }
          await savePrivateKey(parsed.user, parsed.priv, vaultKeyRef.current);
          if (parsed.spk) {
            await saveSpkPrivate(parsed.user, parsed.spk, vaultKeyRef.current);
          }
          if (Array.isArray(parsed.opks)) {
            await saveOpks(parsed.user, parsed.opks, vaultKeyRef.current);
          }
          addCommandResult(
            `✓ Successfully imported private keys for '${parsed.user}'. Now run: /login ${parsed.user}`,
            activePeer ?? undefined,
          );
        } catch {
          addCommandResult("Failed to import key. Invalid format or corruption.", activePeer ?? undefined);
        }
        break;
      }

      default:
        if (cmd.startsWith("/")) {
          addCommandResult(`Unknown command: ${command}. Type /help`, activePeer ?? undefined);
        } else if (!username) {
          addCommandResult("You must /register or /login first.", activePeer ?? undefined);
        } else if (!privateKeyRef.current) {
          addCommandResult(
            `Cannot send message: No private key found for '${username}' on this device.\n` +
            `Run /register ${username} to generate keys on this browser, or /register <new_name>.`,
            activePeer ?? undefined,
          );
        } else if (!activePeer) {
          addCommandResult(
            "No active chat. Click a contact or use /new <username>.",
            activePeer ?? undefined,
          );
        } else if (tofuMismatchesRef.current.has(activePeer)) {
          addCommandResult(
            `🚨 Send blocked: Identity key mismatch detected for '${activePeer}'! Verify safety numbers with /verify and type /trust ${activePeer} to proceed.`,
            activePeer,
          );
        } else if (!ratchetRef.current?.sendingChainKey) {
          addCommandResult(
            `No session with ${activePeer}. Use /new ${activePeer} first.`,
            activePeer,
          );
        } else if (!wsAuthed) {
          addCommandResult("WebSocket not authenticated yet. Connecting...", activePeer);
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
            addCommandResult("Failed to encrypt message.", activePeer);
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
    <div className="flex h-screen bg-[#070b08] text-[#00ff41] font-mono overflow-hidden select-none">
      {/* Sidebar Contacts */}
      {sidebarOpen && (
        <div className="w-56 shrink-0 border-r border-[#003814] flex flex-col bg-[#030a05] select-none">
          <div className="px-3.5 py-2.5 border-b border-[#003814] flex items-center justify-between bg-[#041208]/60">
            <div className="flex items-center gap-1.5">
              <span className="text-[#00ff41] font-bold text-xs tracking-wider">
                CONTACTS
              </span>
              <span className="text-[10px] text-[#006622] font-mono">
                ({contacts.length})
              </span>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => {
                  setInput("/new ");
                  inputRef.current?.focus();
                }}
                className="text-[11px] px-1.5 py-0.5 rounded bg-[#002b0e] border border-[#00551c] text-[#00ff66] hover:bg-[#004417] transition-all"
                title="Start new encrypted session (/new <username>)"
              >
                + New
              </button>
              <button
                onClick={() => setSidebarOpen(false)}
                className="text-[#006622] hover:text-[#00ff41] text-xs px-1"
                title="Collapse sidebar"
              >
                «
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto py-1.5 space-y-0.5">
            {contacts.length === 0 ? (
              <div className="px-3 py-6 text-center text-[#00551a] text-xs leading-relaxed">
                No active contacts yet.
                <br />
                <button
                  onClick={() => {
                    setInput("/new ");
                    inputRef.current?.focus();
                  }}
                  className="mt-2 text-[#00ff66] underline hover:text-[#00e5ff] text-[11px]"
                >
                  Type /new &lt;user&gt;
                </button>
              </div>
            ) : (
              contacts.map((c) => {
                const isActive = c === activePeer;
                return (
                  <button
                    key={c}
                    onClick={() => switchToPeer(c)}
                    className={`w-full text-left px-3 py-2 flex items-center justify-between text-xs transition-all ${
                      isActive
                        ? "bg-[#00260c] border-l-2 border-[#00ff66] text-[#00ff66] font-semibold shadow-[inset_0_0_12px_rgba(0,255,102,0.08)]"
                        : "text-[#00aa33] hover:bg-[#001708] hover:text-[#00ff88]"
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        className={`w-5 h-5 rounded flex items-center justify-center text-[10px] font-bold shrink-0 ${
                          isActive
                            ? "bg-[#00e5ff]/20 text-[#00e5ff] border border-[#00e5ff]/40"
                            : "bg-[#00280f] text-[#008828]"
                        }`}
                      >
                        {c.charAt(0).toUpperCase()}
                      </span>
                      <span className="truncate">{c}</span>
                    </div>
                    {isActive ? (
                      <span className="text-[9px] uppercase px-1 py-0.2 rounded bg-[#00ff66]/10 text-[#00ff66] border border-[#00ff66]/30">
                        Active
                      </span>
                    ) : (
                      <span className="text-[10px] text-[#004414] font-mono">
                        E2EE
                      </span>
                    )}
                  </button>
                );
              })
            )}
          </div>

          {/* User profile at bottom of sidebar */}
          <div className="px-3 py-2.5 border-t border-[#003814] bg-[#020804] flex items-center justify-between text-xs">
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="w-5 h-5 rounded-full bg-[#ffb000]/20 border border-[#ffb000]/40 text-[#ffb000] flex items-center justify-center text-[10px] font-bold shrink-0">
                {username ? username.charAt(0).toUpperCase() : "?"}
              </span>
              <span className="text-[#ffb000] font-semibold truncate text-[11px]">
                {username || "anon"}
              </span>
            </div>
            {username && (
              <button
                onClick={() => handleCommand("/logout")}
                className="text-[10px] text-[#ff4444]/70 hover:text-[#ff4444] hover:underline"
                title="Logout session"
              >
                Logout
              </button>
            )}
          </div>
        </div>
      )}

      {/* Main Terminal Column */}
      <div className="flex-1 flex flex-col min-w-0 bg-[#070b08]">
        {/* Top Header Bar */}
        <div className="flex items-center justify-between border-b border-[#003814] px-4 py-2 select-none shrink-0 bg-[#040e06]/80 backdrop-blur-sm">
          <div className="flex items-center gap-3 min-w-0">
            {!sidebarOpen && (
              <button
                onClick={() => setSidebarOpen(true)}
                className="text-[#00aa33] hover:text-[#00ff41] text-xs px-1.5 py-0.5 rounded border border-[#004414] bg-[#001708]"
                title="Open contacts sidebar"
              >
                » Contacts
              </button>
            )}
            <span className="text-[#00ff41] font-extrabold tracking-widest text-sm drop-shadow-[0_0_8px_rgba(0,255,65,0.4)]">
              SENTINEL
            </span>
            <span className="text-[#003314]">|</span>
            <span
              className={`text-[11px] font-semibold px-2 py-0.5 rounded border flex items-center gap-1.5 ${
                connStatus === "online"
                  ? "text-[#00ff66] bg-[#00ff66]/10 border-[#00ff66]/30"
                  : connStatus === "connecting"
                    ? "text-[#ffb000] bg-[#ffb000]/10 border-[#ffb000]/30"
                    : "text-[#ff4444] bg-[#ff4444]/10 border-[#ff4444]/30"
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
              {connStatus.toUpperCase()}
            </span>

            <button
              onClick={() => handleCommand("/shield")}
              className={`text-[10px] font-semibold px-2 py-0.5 rounded border flex items-center gap-1 transition-all ${
                screenShield
                  ? "text-[#00e5ff] bg-[#00e5ff]/10 border-[#00e5ff]/30 hover:bg-[#00e5ff]/20"
                  : "text-[#888888] bg-[#222222]/50 border-[#444444] hover:text-[#ffffff]"
              }`}
              title="Toggle Native Anti-Screen Capture / Display Affinity (Win32 API)"
            >
              <span>{screenShield ? "🛡️" : "⚠️"}</span>
              <span className="hidden sm:inline">Shield: {screenShield ? "ON" : "OFF"}</span>
            </button>

            <button
              onClick={() => handleCommand("/cloud-config")}
              className={`text-[10px] font-semibold px-2 py-0.5 rounded border flex items-center gap-1 transition-all ${
                cloudStatus.configured
                  ? "text-[#ffaa00] bg-[#ffaa00]/10 border-[#ffaa00]/30 hover:bg-[#ffaa00]/20"
                  : "text-[#666666] bg-[#1a1a1a]/40 border-[#333333] hover:text-[#aaaaaa]"
              }`}
              title={
                cloudStatus.configured
                  ? `Firebase Cloud Vault Active (${cloudStatus.projectId})`
                  : "Firebase Cloud Vault Unconfigured. Click to setup."
              }
            >
              <span>☁️</span>
              <span className="hidden md:inline">
                {cloudStatus.configured ? "Cloud: ON" : "Cloud: SETUP"}
              </span>
            </button>

            {activePeer && (
              <div className="flex items-center gap-2">
                <span className="text-[#003314]">|</span>
                <span className="text-[#00e5ff] font-bold text-xs flex items-center gap-1 bg-[#00e5ff]/10 border border-[#00e5ff]/30 px-2 py-0.5 rounded">
                  <span>🔒</span> {activePeer}
                </span>
                <span className="text-[#00ff66] text-[10px] tracking-wider uppercase px-1.5 py-0.5 rounded bg-[#00ff66]/10 border border-[#00ff66]/20 font-semibold hidden md:inline-block">
                  E2EE ACTIVE
                </span>
                {disappearMs && (
                  <span className="text-[#ffb000] text-[10px] px-1.5 py-0.5 rounded bg-[#ffb000]/10 border border-[#ffb000]/25 font-mono">
                    ⏱️ {formatDuration(disappearMs)}
                  </span>
                )}
              </div>
            )}
          </div>

          <div className="flex items-center gap-2 text-xs">
            {username && (
              <button
                onClick={() => lockSession("User clicked Lock button")}
                className="text-[11px] px-2 py-0.5 rounded bg-[#00220a] border border-[#00551a] text-[#ffb000] hover:bg-[#003d12] hover:border-[#ffb000]/50 transition-all font-mono"
                title="Lock session & scrub in-memory cryptographic keys (Ctrl+L)"
              >
                🔒 Lock
              </button>
            )}
            {activePeer ? (
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => handleCommand("/verify")}
                  className="text-[11px] px-2 py-0.5 rounded bg-[#00220a] border border-[#00551a] text-[#00ff66] hover:bg-[#003d12] hover:border-[#00ff66]/50 transition-all font-mono"
                  title="Verify Safety Number with active peer"
                >
                  🛡️ Verify
                </button>
                <button
                  onClick={() =>
                    handleCommand(
                      disappearMs ? "/disappear off" : "/disappear 5m",
                    )
                  }
                  className="text-[11px] px-2 py-0.5 rounded bg-[#00220a] border border-[#00551a] text-[#ffb000] hover:bg-[#003d12] hover:border-[#ffb000]/50 transition-all font-mono hidden sm:inline-block"
                  title="Toggle 5m disappearing messages"
                >
                  ⏱️ {disappearMs ? "TTL Off" : "TTL 5m"}
                </button>
                <button
                  onClick={() => handleCommand("/clear")}
                  className="text-[11px] px-2 py-0.5 rounded bg-[#00220a] border border-[#00551a] text-[#00aa33] hover:text-[#ff4444] hover:border-[#ff4444]/40 hover:bg-[#200000] transition-all font-mono"
                  title="Clear chat history view"
                >
                  🧹 Clear
                </button>
              </div>
            ) : (
              <div className="text-xs">
                {username ? (
                  <span>
                    <span className="text-[#ffb000] font-semibold">
                      {username}
                    </span>
                    <span className="text-[#00aa2a]">@sentinel</span>
                  </span>
                ) : (
                  <span className="text-[#00551a]">not authenticated</span>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Main Terminal Chat & Command Feed */}
        <div className="flex-1 overflow-y-auto px-4 py-3 text-sm leading-relaxed space-y-2 font-mono scroll-smooth select-text">
          {displayedMessages.length === 0 ? (
            !activePeer ? (
              // Welcome Hero Banner when no chat is open
              <div className="py-8 flex flex-col items-center justify-center text-center max-w-xl mx-auto space-y-4 select-none">
                <pre className="text-[#00ff41] text-[10px] sm:text-[11px] leading-tight opacity-75 font-mono drop-shadow-[0_0_8px_rgba(0,255,65,0.2)]">
{`
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
`}
                </pre>
                <div className="text-xs text-[#00aa2a] font-semibold tracking-wider uppercase">
                  End-to-End Encrypted Terminal • Forward Secrecy • Zero Plaintext Storage
                </div>
                <div className="text-xs text-[#006622] max-w-md leading-relaxed font-mono">
                  Select a contact on the left or type{" "}
                  <code className="text-[#00ff66] bg-[#00220a] px-1 py-0.5 rounded border border-[#004414]">
                    /new &lt;username&gt;
                  </code>{" "}
                  to establish a post-compromise secure session.
                </div>
                <div className="flex flex-wrap justify-center gap-2 pt-2">
                  <button
                    onClick={() => handleCommand("/help")}
                    className="text-xs px-2.5 py-1 rounded bg-[#001f0a] border border-[#00551a] text-[#00ff41] hover:bg-[#003810] transition-colors"
                  >
                    📖 /help
                  </button>
                  <button
                    onClick={() => handleCommand("/status")}
                    className="text-xs px-2.5 py-1 rounded bg-[#001f0a] border border-[#00551a] text-[#00ff41] hover:bg-[#003810] transition-colors"
                  >
                    ⚡ /status
                  </button>
                  <button
                    onClick={() => handleCommand("/chats")}
                    className="text-xs px-2.5 py-1 rounded bg-[#001f0a] border border-[#00551a] text-[#00ff41] hover:bg-[#003810] transition-colors"
                  >
                    👥 /chats
                  </button>
                </div>
              </div>
            ) : (
              <div className="py-12 flex flex-col items-center justify-center text-center space-y-2 text-xs select-none">
                <div className="text-[#00e5ff] font-semibold text-sm flex items-center gap-1.5">
                  <span>🔒</span> Secure E2EE Channel Established with {activePeer}
                </div>
                <div className="text-[#00551a] max-w-md font-mono">
                  Messages are end-to-end encrypted with X3DH & Double Ratchet with constant-size padding.
                </div>
                <div className="flex gap-2 pt-2">
                  <button
                    onClick={() => handleCommand("/verify")}
                    className="px-2.5 py-1 rounded bg-[#00220a] border border-[#00551a] text-[#00ff66] hover:bg-[#003810] transition-all font-mono"
                  >
                    🛡️ Verify Safety Number
                  </button>
                  <button
                    onClick={() => handleCommand("/disappear 5m")}
                    className="px-2.5 py-1 rounded bg-[#00220a] border border-[#00551a] text-[#ffb000] hover:bg-[#003810] transition-all font-mono"
                  >
                    ⏱️ Set 5m Disappear
                  </button>
                </div>
              </div>
            )
          ) : (
            displayedMessages.map((msg) => (
              <div
                key={msg.id}
                className="group flex gap-2.5 items-start py-0.5 hover:bg-[#041207]/40 px-2 rounded transition-colors"
              >
                {/* Timestamp */}
                <span className="text-[#00551a] text-[11px] shrink-0 w-16 pt-0.5 font-mono select-none text-right">
                  {formatTime(msg.timestamp)}
                </span>

                {/* Sender Badge */}
                <span className="shrink-0 w-20 pt-0.5 flex justify-end">
                  {msg.type === "user" && (
                    <span className="text-[#ffb000] font-semibold text-[11px] px-1.5 py-0.2 rounded bg-[#ffb000]/10 border border-[#ffb000]/30 select-none">
                      you
                    </span>
                  )}
                  {msg.type === "peer" && (
                    <span
                      className="text-[#00e5ff] font-semibold text-[11px] px-1.5 py-0.2 rounded bg-[#00e5ff]/10 border border-[#00e5ff]/30 select-none truncate max-w-full text-right"
                      title={msg.peer || activePeer || "peer"}
                    >
                      {msg.peer || activePeer || "peer"}
                    </span>
                  )}
                  {msg.type === "command" && (
                    <span className="text-[#c084fc] font-semibold text-[11px] px-1.5 py-0.2 rounded bg-[#a855f7]/15 border border-[#a855f7]/30 select-none">
                      cmd
                    </span>
                  )}
                  {msg.type === "system" && (
                    <span className="text-[#00ff41] font-semibold text-[11px] px-1.5 py-0.2 rounded bg-[#00ff41]/10 border border-[#00ff41]/30 select-none">
                      sys
                    </span>
                  )}
                </span>

                {/* Message Content */}
                <div className="flex-1 min-w-0">
                  {msg.type === "system" ? (
                    <div className="text-[#99e6aa] text-xs font-mono whitespace-pre-wrap leading-relaxed bg-[#021808]/70 border-l-2 border-[#00ff41]/50 px-3 py-1.5 rounded-r shadow-sm">
                      {msg.text}
                    </div>
                  ) : msg.type === "command" ? (
                    <div className="text-[#e9d5ff] font-mono text-sm flex items-center gap-1.5">
                      <span className="text-[#a855f7] font-bold select-none">
                        $
                      </span>
                      <span className="font-semibold">{msg.text}</span>
                    </div>
                  ) : msg.type === "user" ? (
                    <div className="text-[#00ff66] text-sm break-words leading-relaxed font-mono">
                      {msg.text}
                    </div>
                  ) : (
                    <div className="text-[#e2f7fa] text-sm break-words leading-relaxed font-mono">
                      {getCleanMessageText(msg)}
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
          <div ref={bottomRef} />
        </div>

        {/* Quick Commands Bar above input */}
        <div className="px-4 py-1.5 flex items-center gap-2 overflow-x-auto text-[11px] border-t border-[#00280c] bg-[#020b04] select-none scrollbar-none">
          <span className="text-[#006622] shrink-0 font-semibold tracking-wider text-[10px]">
            QUICK CMDS:
          </span>
          {[
            { label: "/help", cmd: "/help" },
            { label: "/verify 🛡️", cmd: "/verify" },
            { label: "/disappear 5m ⏱️", cmd: "/disappear 5m" },
            { label: "/status ⚡", cmd: "/status" },
            { label: "/backup ☁️", cmd: "/cloud-backup " },
            { label: "/restore ☁️", cmd: "/cloud-restore " },
            { label: "/chats 👥", cmd: "/chats" },
            { label: "/shield 🛡️", cmd: "/shield" },
            { label: "/lock 🔒", cmd: "/lock" },
            { label: "/clear 🧹", cmd: "/clear" },
          ].map((chip) => (
            <button
              key={chip.label}
              onClick={() => handleCommand(chip.cmd)}
              className="px-2 py-0.5 rounded bg-[#001f08] border border-[#004414] text-[#00dd3a] hover:bg-[#003810] hover:text-[#00ff41] hover:border-[#00ff41]/50 transition-all shrink-0 font-mono text-[11px]"
            >
              {chip.label}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="border-t border-[#003311] bg-[#040f06] px-4 py-2.5 flex items-center gap-2.5 shrink-0">
          <span className="text-[#00ff41] font-mono shrink-0 select-none text-xs flex items-center gap-1">
            <span className="text-[#ffb000] font-semibold">
              {username || "anon"}
            </span>
            <span className="text-[#00aa2a]">@sentinel</span>
            <span className="text-[#00ff41]">:~$</span>
          </span>
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
            className="flex-1 bg-transparent border-none outline-none text-[#00ff41] caret-[#00ff41] font-mono text-sm placeholder-[#004414]"
            placeholder={
              activePeer
                ? disappearMs
                  ? `Message ${activePeer} (TTL ${formatDuration(disappearMs)})... or type /command`
                  : `Message ${activePeer}... or type /command`
                : "Type a command e.g. /new <user>, /help, /chats..."
            }
            spellCheck={false}
            autoComplete="off"
            autoCorrect="off"
          />
          <button
            onClick={() => {
              if (input.trim()) {
                const val = input.trim();
                setInput("");
                handleCommand(val);
              }
            }}
            className="px-3 py-1 rounded bg-[#00220a] border border-[#00551a] text-[#00ff41] hover:bg-[#003d12] hover:border-[#00ff66]/50 text-xs font-mono transition-all select-none shrink-0"
            title="Send message or execute command (Enter)"
          >
            Send ↵
          </button>
        </div>

        {/* Status Footer */}
        <div className="px-4 py-1 text-[10px] text-[#004414] flex justify-between select-none shrink-0 bg-[#020703] border-t border-[#00220a]">
          <span className="flex items-center gap-2">
            <span>
              {connStatus === "online" ? "BACKEND ONLINE" : "BACKEND OFFLINE"}
            </span>
            <span>•</span>
            <span>X3DH + DOUBLE RATCHET + AES-GCM</span>
          </span>
          <span>v0.2.0-dev</span>
        </div>
      </div>

      {/* Fullscreen Session Lock Screen Overlay */}
      {isLocked && (
        <div className="fixed inset-0 z-50 bg-[#010602]/95 backdrop-blur-md flex flex-col items-center justify-center p-4 font-mono select-none">
          <div className="w-16 h-16 rounded-full bg-[#ffb000]/10 border border-[#ffb000]/40 flex items-center justify-center text-3xl mb-4 text-[#ffb000] drop-shadow-[0_0_15px_rgba(255,176,0,0.3)] animate-pulse">
            🔒
          </div>

          <h2 className="text-xl font-bold tracking-widest text-[#00ff41] uppercase drop-shadow-[0_0_10px_rgba(0,255,65,0.4)]">
            SESSION LOCKED
          </h2>
          <div className="text-xs text-[#00aa2a] mt-1 text-center">
            Cryptographic memory scrubbed • Ratchet state zeroized
          </div>

          <div className="mt-6 p-4 rounded bg-[#020b04] border border-[#003810] text-xs max-w-sm w-full space-y-2.5">
            <div className="flex justify-between items-center text-[#00882b]">
              <span>Active Identity:</span>
              <span className="text-[#ffb000] font-semibold">{username || "None"}</span>
            </div>
            <div className="flex justify-between items-center text-[#00882b]">
              <span>Vault Security:</span>
              <span className="text-[#00e5ff]">
                {username && hasVaultConfigured(username)
                  ? "PBKDF2 + AES-GCM Vault"
                  : "Unencrypted Session"}
              </span>
            </div>
            <div className="flex justify-between items-center text-[#00882b]">
              <span>RAM Protection:</span>
              <span className="text-[#00ff66] font-semibold">Zeroized (Scrubbed)</span>
            </div>
            <div className="flex justify-between items-center text-[#00882b]">
              <span>Screen Defense:</span>
              <span className="text-[#00e5ff]">{screenShield ? "Active (Affinity WDA)" : "Disabled"}</span>
            </div>
          </div>

          <div className="mt-4 max-w-sm w-full">
            {username && hasVaultConfigured(username) ? (
              <div className="space-y-3">
                <input
                  type="password"
                  placeholder="Enter vault passphrase to unlock..."
                  value={unlockInput}
                  onChange={(e) => {
                    setUnlockInput(e.target.value);
                    if (unlockError) setUnlockError(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      void unlockSession(unlockInput);
                    }
                  }}
                  className="w-full px-3 py-2 bg-[#001708] border border-[#00551a] focus:border-[#00ff66] rounded outline-none text-[#00ff66] text-sm text-center font-mono placeholder-[#004414]"
                  autoFocus
                />
                {unlockError && (
                  <div className="text-[#ff4444] text-xs text-center font-semibold">
                    {unlockError}
                  </div>
                )}
                <button
                  onClick={() => void unlockSession(unlockInput)}
                  className="w-full py-2 rounded bg-[#003810] border border-[#007722] hover:bg-[#004d16] hover:border-[#00aa33] text-[#00ff41] font-semibold text-xs tracking-wider uppercase transition-all shadow-[0_0_10px_rgba(0,255,65,0.15)]"
                >
                  Unlock Session ↵
                </button>
              </div>
            ) : (
              <button
                onClick={() => void unlockSession()}
                className="w-full py-2.5 rounded bg-[#003810] border border-[#007722] hover:bg-[#004d16] hover:border-[#00aa33] text-[#00ff41] font-semibold text-xs tracking-wider uppercase transition-all shadow-[0_0_10px_rgba(0,255,65,0.15)]"
                autoFocus
              >
                Resume Session ↵
              </button>
            )}

            <div className="mt-4 flex items-center justify-between text-[11px] text-[#00551a]">
              <span>Tip: Hotkey <kbd className="text-[#00aa2a] bg-[#001f0a] px-1 py-0.5 rounded border border-[#004414]">Ctrl+L</kbd> to lock</span>
              <button
                onClick={executePanic}
                className="text-[#ff4444] hover:underline hover:text-[#ff6666] font-semibold"
                title="Immediately shred all keys and local data"
              >
                Emergency Panic
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
