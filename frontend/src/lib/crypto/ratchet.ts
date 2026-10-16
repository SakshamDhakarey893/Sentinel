import { exportPrivateKey, importPrivateKey, importPublicKey } from "./keys";
import { zeroizeBuffer, encryptWithVaultKey, decryptWithVaultKey } from "./vault";

export async function importHmacKey(raw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

export async function hmac(key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
  return crypto.subtle.sign("HMAC", key, data);
}

export async function kdfChainKey(
  chainKey: ArrayBuffer,
): Promise<{ messageKey: ArrayBuffer; nextChainKey: ArrayBuffer }> {
  const key = await importHmacKey(chainKey);
  const messageKey = await hmac(key, new Uint8Array([0x01]));
  const nextChainKey = await hmac(key, new Uint8Array([0x02]));
  return { messageKey, nextChainKey };
}

export async function kdfRootKey(
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

export async function kdfX3DH(dhOutputs: ArrayBuffer[]): Promise<ArrayBuffer> {
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

export function padPlaintext(plaintext: string): Uint8Array {
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

export function unpadPlaintext(decryptedBytes: Uint8Array): string {
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

export async function encryptWithMessageKey(
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

export async function decryptWithMessageKey(
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

export function bufToB64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function b64ToBuf(b64: string): ArrayBuffer {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
}

export type StoredRatchet = {
  rootKey: string;
  sendingChainKey: string | null;
  receivingChainKey: string | null;
  sendN: number;
  recvN: number;
  dhPublicB64: string;
  dhPrivateB64: string;
  remoteDhPublicB64: string | null;
};

export type RatchetState = {
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

export function zeroizeRatchetState(state: RatchetState | null) {
  if (!state) return;
  zeroizeBuffer(state.rootKey);
  if (state.sendingChainKey) zeroizeBuffer(state.sendingChainKey);
  if (state.receivingChainKey) zeroizeBuffer(state.receivingChainKey);
}

export async function serializeRatchet(state: RatchetState): Promise<StoredRatchet> {
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

export async function deserializeRatchet(s: StoredRatchet): Promise<RatchetState> {
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

export function sessionStorageKey(username: string, peer: string) {
  return `sentinel_session_${username}_${peer}`;
}

export async function saveSession(
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

export async function loadSession(
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

export function listSavedPeers(username: string): string[] {
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

export function clearPeerSession(username: string, peer: string) {
  localStorage.removeItem(sessionStorageKey(username, peer));
}
