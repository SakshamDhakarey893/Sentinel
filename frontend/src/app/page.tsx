"use client";

import { useState, useRef, useEffect, KeyboardEvent, useCallback } from "react";
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
import {
  authenticateWithRelay,
  getStoredSessionToken,
  saveStoredSessionToken,
  clearStoredSessionToken,
} from "@/lib/authClient";

import {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  exportPrivateKey,
  importPrivateKey,
  deriveSharedSecret,
  extractPublicKeyFromPkcs8,
} from "@/lib/crypto/keys";
import {
  importHmacKey,
  hmac,
  kdfChainKey,
  kdfRootKey,
  kdfX3DH,
  encryptWithMessageKey,
  decryptWithMessageKey,
  padPlaintext,
  unpadPlaintext,
  RatchetState,
  StoredRatchet,
  zeroizeRatchetState,
  saveSession,
  loadSession,
  listSavedPeers,
  clearPeerSession,
  sessionStorageKey,
  serializeRatchet,
  deserializeRatchet,
} from "@/lib/crypto/ratchet";
import {
  computeSafetyNumber,
  computeVisualEmojiHash,
  generateTerminalQr,
  EMOJI_FINGERPRINT_POOL,
} from "@/lib/crypto/safety";
import {
  deriveVaultKey,
  encryptWithVaultKey,
  decryptWithVaultKey,
  setupNewVault,
  unlockVault,
  hasVaultConfigured,
  savePublicKey,
  loadPublicKey,
  savePrivateKey,
  loadPrivateKey,
  saveSpkPrivate,
  loadSpkPrivate,
  saveOpks,
  loadOpks,
  saveChatHistory,
  loadChatHistory,
  clearChatHistory,
  listSavedChatPeers,
  ChatMessage,
  parseDuration,
  formatDuration,
  saveDisappearMs,
  loadDisappearMs,
  CANARY_PAYLOAD,
  zeroizeBuffer,
} from "@/lib/crypto/vault";
import {
  TofuStatus,
  TofuRecord,
  getTofuRecord,
  saveTofuRecord,
  checkTofu,
} from "@/lib/crypto/tofu";
import { setScreenProtection } from "@/lib/crypto/screenProtection";

type Message = {
  id: string;
  type: "system" | "user" | "peer" | "command";
  text: string;
  timestamp: Date;
  peer?: string;
  isCmdResult?: boolean;
};

type ConnStatus =
  | "connecting"
  | "connected"
  | "online"
  | "offline"
  | "auth_failed";

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
  const wsAuthedRef = useRef<boolean>(false);
  const authRetryCountRef = useRef<number>(0);
  const [hasKeys, setHasKeys] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [logOpen, setLogOpen] = useState(true);
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
  const consoleBottomRef = useRef<HTMLDivElement>(null);
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
  const sessionTokenRef = useRef<string | null>(null);
  const sessionPassphraseRef = useRef<string | null>(null);
  const syncTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const isSyncingRef = useRef<boolean>(false);

  const pendingCiphertextsRef = useRef<
    Map<string, { id: string; header: any; body: string; from: string }[]>
  >(new Map());

  useEffect(() => {
    usernameRef.current = username;
  }, [username]);

  useEffect(() => {
    activePeerRef.current = activePeer;
    if (activePeer) {
      setLogOpen(false);
    } else {
      setLogOpen(true);
    }
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

    if (syncTimeoutRef.current) {
      clearTimeout(syncTimeoutRef.current);
      syncTimeoutRef.current = null;
    }
    sessionPassphraseRef.current = null;
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
    clearStoredSessionToken();
    sessionTokenRef.current = null;

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
      if (passphrase) {
        sessionPassphraseRef.current = passphrase;
        requestSync("unlock", 2000);
      }
      addCommandResult(
        "✓ Session unlocked. In-memory keys restored.",
        activePeerRef.current ?? undefined,
      );
      return true;
    },
    [addCommandResult],
  );

  const triggerCloudSync = useCallback(
    async (reason: string = "periodic") => {
      const currentName = usernameRef.current;
      const passphrase = sessionPassphraseRef.current;
      const privKey = privateKeyRef.current;

      if (!currentName || !passphrase || !privKey || isSyncingRef.current) {
        return;
      }

      const fbStatus = getFirebaseStatus();
      if (!fbStatus.configured) {
        logBackground(`Cloud auto-sync skipped (${reason}): Firebase not configured.`);
        return;
      }

      try {
        isSyncingRef.current = true;
        logBackground(`☁️ Starting Zero-Knowledge Cloud auto-sync (${reason})...`);

        const privB64 = await exportPrivateKey(privKey);
        const spkB64 = spkPrivateRef.current
          ? await exportPrivateKey(spkPrivateRef.current)
          : null;

        const allPeers = Array.from(
          new Set([
            ...contacts,
            ...listSavedPeers(currentName),
            ...listSavedChatPeers(currentName),
          ]),
        );

        const ratchetsSnapshot: Record<string, any> = {};
        for (const peer of allPeers) {
          const memRatchet = ratchetsByPeerRef.current.get(peer);
          if (memRatchet) {
            try {
              ratchetsSnapshot[peer] = await serializeRatchet(memRatchet);
            } catch {}
          } else {
            const rawSession = localStorage.getItem(
              sessionStorageKey(currentName, peer),
            );
            if (rawSession) {
              try {
                const parsed = JSON.parse(rawSession);
                if (parsed.v === 2 && parsed.enc && vaultKeyRef.current) {
                  const dec = await decryptWithVaultKey(
                    vaultKeyRef.current,
                    parsed.enc,
                  );
                  ratchetsSnapshot[peer] = JSON.parse(dec);
                } else {
                  ratchetsSnapshot[peer] = parsed;
                }
              } catch {}
            }
          }
        }

        const historiesSnapshot: Record<string, any> = {};
        for (const peer of allPeers) {
          const msgs = await loadChatHistory(
            currentName,
            peer,
            vaultKeyRef.current,
          );
          if (msgs && msgs.length > 0) {
            historiesSnapshot[peer] = msgs.map((m) => ({
              id: m.id,
              type: m.type,
              text: m.text,
              timestamp:
                m.timestamp instanceof Date
                  ? m.timestamp.toISOString()
                  : String(m.timestamp),
              peer: m.peer || peer,
            }));
          }
        }

        const payload: CloudVaultPayload = {
          username: currentName,
          publicKeyB64:
            myPublicKeyB64Ref.current || loadPublicKey(currentName) || undefined,
          privateKeyB64: privB64,
          spkPrivateB64: spkB64,
          opks: opksRef.current,
          contacts: allPeers,
          ratchets: ratchetsSnapshot,
          chatHistories: historiesSnapshot,
          exportedAt: new Date().toISOString(),
        };

        const res = await uploadZeroKnowledgeVault(
          currentName,
          passphrase,
          payload,
        );
        if (res.success) {
          logBackground(`✓ Cloud auto-sync complete (${reason}).`);
        } else {
          logBackground(`⚠️ Cloud auto-sync notice (${reason}): ${res.message}`);
        }
      } catch (err: any) {
        logBackground(
          `⚠️ Cloud auto-sync error (${reason}): ${err?.message || String(err)}`,
        );
      } finally {
        isSyncingRef.current = false;
      }
    },
    [contacts, logBackground],
  );

  const requestSync = useCallback(
    (reason: string = "update", delayMs: number = 2500) => {
      if (syncTimeoutRef.current) {
        clearTimeout(syncTimeoutRef.current);
      }
      syncTimeoutRef.current = setTimeout(() => {
        void triggerCloudSync(reason);
      }, delayMs);
    },
    [triggerCloudSync],
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
          if (type === "user") {
            requestSync("outbound message", 3000);
          }
        }
        return next;
      });
    },
    [requestSync],
  );

  const addContact = useCallback(
    (peer: string) => {
      setContacts((prev) => {
        if (prev.includes(peer)) return prev;
        return [...prev, peer].sort();
      });
      requestSync("new contact", 1000);
    },
    [requestSync],
  );

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
        setUsersCount(data.users_online ?? data.users_registered ?? 0);
        return true;
      }
    } catch {}
    setConnStatus("offline");
    setWsAuthed(false);
    wsAuthedRef.current = false;
    return false;
  }, []);

  const sendWs = useCallback(
    (obj: { type?: string; [key: string]: any }) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        if (obj.type === "message" && !wsAuthedRef.current) {
          logBackground("Outbound message blocked: WebSocket is not authenticated on relay.");
          return;
        }
        wsRef.current.send(JSON.stringify(obj));
      }
    },
    [logBackground],
  );

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

          const token = sessionTokenRef.current || getStoredSessionToken(currentName);
          const appendRes = await fetch(`${getApiBase()}/api/prekeys/append`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(token ? { Authorization: `Bearer ${token}` } : {}),
            },
            body: JSON.stringify({
              username: currentName,
              one_time_prekeys: newOpks.map((o) => o.pub),
              token: token || undefined,
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

  const sendWsAuth = useCallback(
    async (forcedToken?: string) => {
      const u = usernameRef.current;
      if (!u) return false;
      if (wsRef.current?.readyState !== WebSocket.OPEN) return false;

      let token = forcedToken || sessionTokenRef.current || getStoredSessionToken(u);
      if (!token && privateKeyRef.current) {
        logBackground(`Solving cryptographic challenge from relay for '${u}'...`);
        const authRes = await authenticateWithRelay(
          getApiBase(),
          u,
          privateKeyRef.current,
        );
        if (authRes.success && authRes.token) {
          token = authRes.token;
          sessionTokenRef.current = token;
          saveStoredSessionToken(u, token);
        } else {
          addCommandResult(
            `⚠️ Relay challenge authentication failed: ${authRes.error}`,
            activePeerRef.current ?? undefined,
          );
          setConnStatus("auth_failed");
          wsAuthedRef.current = false;
          setWsAuthed(false);
          return false;
        }
      }

      setConnStatus("connected");
      wsRef.current.send(
        JSON.stringify({
          type: "auth",
          username: u,
          token: token || undefined,
        }),
      );
      return true;
    },
    [getApiBase, addCommandResult, logBackground],
  );

  const connectWs = useCallback(
    (customWsUrl?: string, forceReauth?: boolean) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        if (forceReauth || !wsAuthedRef.current) {
          void sendWsAuth();
        }
        return;
      }
      if (wsRef.current?.readyState === WebSocket.CONNECTING) {
        return;
      }

      try {
        setConnStatus("connecting");
        const targetWs = customWsUrl || serverConfigRef.current.wsUrl;
        const ws = new WebSocket(targetWs);
        wsRef.current = ws;

        ws.onopen = async () => {
          setConnStatus("connected");
          addMessage("system", `Connected to Sentinel relay (${targetWs})`);
          if (usernameRef.current) {
            await sendWsAuth();
          }
        };

        ws.onmessage = async (evt) => {
          try {
            const msg = JSON.parse(evt.data);

            switch (msg.type) {
              case "auth_ok":
                wsAuthedRef.current = true;
                setWsAuthed(true);
                setConnStatus("online");
                authRetryCountRef.current = 0;
                if (typeof msg.users_authenticated === "number") {
                  setUsersCount(msg.users_authenticated);
                }
                addCommandResult(
                  `✓ WebSocket authenticated as ${msg.username} [RELAY ONLINE]`,
                  activePeerRef.current ?? undefined,
                );
                break;

              case "auth_error": {
                wsAuthedRef.current = false;
                setWsAuthed(false);
                setConnStatus("auth_failed");
                addCommandResult(
                  `❌ Relay Auth error: ${msg.message}`,
                  activePeerRef.current ?? undefined,
                );

                if (
                  authRetryCountRef.current === 0 &&
                  usernameRef.current &&
                  privateKeyRef.current
                ) {
                  authRetryCountRef.current = 1;
                  const u = usernameRef.current;
                  addCommandResult(
                    `[Relay] Session token rejected or expired. Solving cryptographic challenge to renew token...`,
                    activePeerRef.current ?? undefined,
                  );
                  clearStoredSessionToken(u);
                  sessionTokenRef.current = null;
                  void (async () => {
                    const authRes = await authenticateWithRelay(
                      getApiBase(),
                      u,
                      privateKeyRef.current!,
                    );
                    if (authRes.success && authRes.token) {
                      sessionTokenRef.current = authRes.token;
                      saveStoredSessionToken(u, authRes.token);
                      addCommandResult(
                        `✓ Renewed session token via relay challenge. Re-authenticating WebSocket...`,
                        activePeerRef.current ?? undefined,
                      );
                      if (wsRef.current?.readyState === WebSocket.OPEN) {
                        wsRef.current.send(
                          JSON.stringify({
                            type: "auth",
                            username: u,
                            token: authRes.token,
                          }),
                        );
                      }
                    } else {
                      addCommandResult(
                        `❌ Challenge-response token renewal failed: ${authRes.error}`,
                        activePeerRef.current ?? undefined,
                      );
                    }
                  })();
                }
                break;
              }

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
        wsAuthedRef.current = false;
        setWsAuthed(false);
        wsRef.current = null;
        setTimeout(() => connectWs(), 5000);
      };

      ws.onerror = () => {
        setConnStatus("offline");
        wsAuthedRef.current = false;
        setWsAuthed(false);
      };
    } catch {
      setConnStatus("offline");
      wsAuthedRef.current = false;
      setWsAuthed(false);
    }
  }, [
    sendWsAuth,
    addMessage,
    addContact,
    addCommandResult,
    getApiBase,
    tryDecryptPending,
    scheduleDisappear,
  ]);

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

  const chatMessages = messages.filter(
    (m) =>
      Boolean(activePeer) &&
      m.peer === activePeer &&
      (m.type === "user" || m.type === "peer") &&
      !m.isCmdResult,
  );

  const consoleMessages = messages.filter(
    (m) => m.type === "command" || Boolean(m.isCmdResult) || m.type === "system",
  );

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages, activePeer]);

  useEffect(() => {
    if (logOpen || !activePeer) {
      consoleBottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [consoleMessages, logOpen, activePeer]);

  useEffect(() => {
    if (!username || !hasKeys) return;
    void replenishPrekeys();
    const interval = setInterval(() => {
      void replenishPrekeys();
    }, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, [username, hasKeys, replenishPrekeys]);

  useEffect(() => {
    if (!username || !hasKeys) return;
    const interval = setInterval(() => {
      void triggerCloudSync("periodic (3m)");
    }, 3 * 60 * 1000);
    return () => clearInterval(interval);
  }, [username, hasKeys, triggerCloudSync]);

  // ─── Commands ─────────────────────────────────────────────────────────────

  const handleCommand = async (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;

    const parts = trimmed.split(/\s+/);
    const command = parts[0].toLowerCase();

    if (trimmed.startsWith("/")) {
      // Mask passphrase in command output and history to protect credentials
      const isSensitive =
        command === "/register" ||
        command === "/login" ||
        command === "/cloud-backup" ||
        command === "/backup" ||
        command === "/cloud-restore" ||
        command === "/restore" ||
        command === "/unlock";
      const sanitizedCmd = isSensitive
        ? `${parts[0]}${parts[1] ? " " + parts[1] : ""} ********`
        : trimmed;

      addMessage("command", sanitizedCmd, activePeer ?? undefined);
      if (activePeer) {
        setLogOpen(true);
      }
    }

    switch (command) {
      case "/help":
        addCommandResult(
          `Available commands:
  /help                         Show this help
  /log                          Toggle console & system log drawer
  /register <user> <passphrase> Create identity + vault & auto-backup to cloud
  /login <user> <passphrase>    Login, unlock vault & auto-restore from cloud
  /new <user>                   Start or restore session with user
  /chats                        List contacts / sessions
  /verify                       Show Safety Number & TOFU verification status
  /trust [user]                 Explicitly trust remote Identity Key after rotation
  /shield [on|off]              Toggle Anti-Screen Capture / OBS defense (Win32)
  /lock [mins|off]              Lock terminal immediately (or set auto-lock timer)
  /unlock <passphrase>          Unlock terminal & decrypt in-memory keys
  /disappear <time|off>         Auto-delete msgs (30s, 5m, 1h, off)
  /reset <user>                 Reset broken secure session with user
  /clear                        Clear current chat history view
  /status                       Show status & security parameters
  /server [url|reset]           View, configure, or reset relay server URL
  /cloud-backup [passphrase]    Force Zero-Knowledge backup to Firebase
  /cloud-restore <u p>          Manual restore from Firebase on any device
  /cloud-config [json]          Configure or view Firebase credentials
  /export-key                   Export armored private keys for other devices
  /import-key <key>             Import private keys on this browser
  /logout                       End session & lock vault
  /panic                        Purge memory & shred local storage (Ctrl+Shift+X)

  Hotkeys: Ctrl+L (Lock) | Ctrl+Shift+X (Panic Shred)`,
          activePeer ?? undefined,
        );
        break;

      case "/log":
      case "/console": {
        setLogOpen((prev) => !prev);
        addCommandResult(
          `Console drawer toggled ${!logOpen ? "open" : "closed"}.`,
          activePeer ?? undefined,
        );
        break;
      }

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
        const name = parts[1]?.toLowerCase();
        const passphrase = parts.slice(2).join(" ").trim();
        if (!name || !passphrase) {
          addCommandResult(
            "Usage: /register <username> <passphrase>",
            activePeer ?? undefined,
          );
          break;
        }
        if (passphrase.length < 8) {
          addCommandResult(
            "Passphrase must be at least 8 characters for vault security.",
            activePeer ?? undefined,
          );
          break;
        }
        logBackground(`Registering "${name}" with encrypted master vault...`);

        try {
          // 1. Generate identity, signed prekey, and one-time prekeys
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

          // 2. Setup local master vault using the user passphrase
          const vKey = await setupNewVault(name, passphrase);
          vaultKeyRef.current = vKey;
          setVaultStatus("unlocked");

          // 3. Store encrypted keys locally with the master vault key
          await savePrivateKey(name, privateKeyB64, vKey);
          await saveSpkPrivate(name, spkPriv, vKey);
          await saveOpks(name, opks, vKey);

          privateKeyRef.current = identity.privateKey;
          myPublicKeyB64Ref.current = publicKeyB64;
          savePublicKey(name, publicKeyB64);
          spkPrivateRef.current = spk.privateKey;
          opksRef.current = opks;
          setHasKeys(true);
          sessionPassphraseRef.current = passphrase;

          // 4. Zero-knowledge upload to Firebase Cloud Vault
          const cloudPayload: CloudVaultPayload = {
            username: name,
            publicKeyB64,
            privateKeyB64,
            spkPrivateB64: spkPriv,
            opks,
            contacts: [],
            ratchets: {},
            chatHistories: {},
            exportedAt: new Date().toISOString(),
          };
          const cloudRes = await uploadZeroKnowledgeVault(
            name,
            passphrase,
            cloudPayload,
          );
          if (cloudRes.success) {
            logBackground("✓ Zero-Knowledge Cloud Vault initialized on Firebase.");
          } else {
            logBackground(`Cloud backup notice: ${cloudRes.message}`);
          }

          // 5. Register with relay server
          const existingToken =
            sessionTokenRef.current || getStoredSessionToken(name);
          const res = await fetch(`${getApiBase()}/api/register`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(existingToken
                ? { Authorization: `Bearer ${existingToken}` }
                : {}),
            },
            body: JSON.stringify({
              username: name,
              public_key: publicKeyB64,
              token: existingToken || undefined,
            }),
          });
          const data = await res.json();

          if (!data.success) {
            addCommandResult(
              `Registration error: ${data.message}`,
              activePeer ?? undefined,
            );
            break;
          }

          if (data.token) {
            sessionTokenRef.current = data.token;
            saveStoredSessionToken(name, data.token);
          }

          // 6. Upload prekeys to relay
          const preRes = await fetch(`${getApiBase()}/api/prekeys`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(sessionTokenRef.current
                ? { Authorization: `Bearer ${sessionTokenRef.current}` }
                : {}),
            },
            body: JSON.stringify({
              username: name,
              signed_prekey: spkPub,
              one_time_prekeys: opks.map((o) => o.pub),
              token: sessionTokenRef.current || undefined,
            }),
          });
          await preRes.json();

          setUsername(data.user.username);
          const saved = Array.from(
            new Set([
              ...listSavedPeers(data.user.username),
              ...listSavedChatPeers(data.user.username),
            ]),
          );
          if (saved.length > 0) {
            setContacts(saved);
          }

          authRetryCountRef.current = 0;
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            void sendWsAuth(sessionTokenRef.current || undefined);
          } else {
            connectWs(undefined, true);
          }
          setUsersCount((c) => c + 1);

          addCommandResult(
            `✓ Registered identity "${data.user.username}". Master vault initialized with Zero-Knowledge encryption & auto-sync active.`,
            activePeer ?? undefined,
          );
        } catch (err) {
          console.error(err);
          addCommandResult(
            "Failed to register. Is the backend running?",
            activePeer ?? undefined,
          );
          setConnStatus("offline");
        }
        break;
      }

      case "/login": {
        const name = parts[1]?.toLowerCase();
        const passphrase = parts.slice(2).join(" ").trim();
        if (!name || !passphrase) {
          addCommandResult(
            "Usage: /login <username> <passphrase>",
            activePeer ?? undefined,
          );
          break;
        }
        if (passphrase.length < 8) {
          addCommandResult(
            "Passphrase must be at least 8 characters.",
            activePeer ?? undefined,
          );
          break;
        }
        logBackground(`Logging in as "${name}" with Zero-Knowledge verification...`);

        try {
          let keysLoaded = false;
          let restoredFromCloud = false;

          // 1. Check and try downloading Zero-Knowledge Cloud Vault from Firebase
          const fbStatus = getFirebaseStatus();
          if (fbStatus.configured) {
            logBackground(`Checking Firebase Cloud Vault for "${name}"...`);
            const cloudRes = await downloadZeroKnowledgeVault(name, passphrase);
            if (cloudRes.success && cloudRes.data) {
              const vault = cloudRes.data;
              restoredFromCloud = true;

              // Setup local master vault with this passphrase
              const vKey = await setupNewVault(name, passphrase);
              vaultKeyRef.current = vKey;
              setVaultStatus("unlocked");

              // Save keys encrypted into local storage & memory
              await savePrivateKey(name, vault.privateKeyB64, vKey);
              privateKeyRef.current = await importPrivateKey(vault.privateKeyB64);
              myPublicKeyB64Ref.current =
                vault.publicKeyB64 ||
                extractPublicKeyFromPkcs8(vault.privateKeyB64) ||
                loadPublicKey(name);
              if (myPublicKeyB64Ref.current) {
                savePublicKey(name, myPublicKeyB64Ref.current);
              }

              if (vault.spkPrivateB64) {
                await saveSpkPrivate(name, vault.spkPrivateB64, vKey);
                spkPrivateRef.current = await importPrivateKey(
                  vault.spkPrivateB64,
                );
              }

              if (Array.isArray(vault.opks)) {
                await saveOpks(name, vault.opks, vKey);
                opksRef.current = vault.opks;
              }

              if (Array.isArray(vault.contacts)) {
                setContacts(vault.contacts);
              }

              if (vault.ratchets && typeof vault.ratchets === "object") {
                for (const [peer, rData] of Object.entries(vault.ratchets)) {
                  try {
                    const ratchet = await deserializeRatchet(rData);
                    ratchetsByPeerRef.current.set(peer, ratchet);
                    await saveSession(name, peer, ratchet, vKey);
                  } catch {}
                }
              }

              if (vault.chatHistories && typeof vault.chatHistories === "object") {
                for (const [peer, msgs] of Object.entries(vault.chatHistories)) {
                  if (Array.isArray(msgs)) {
                    const chatMsgs: ChatMessage[] = msgs.map((m: any) => ({
                      id: m.id || crypto.randomUUID(),
                      type: m.type as "user" | "peer",
                      text: m.text,
                      timestamp: new Date(m.timestamp),
                      peer: m.peer || peer,
                    }));
                    await saveChatHistory(name, peer, chatMsgs, vKey);
                  }
                }
              }

              sessionPassphraseRef.current = passphrase;
              setHasKeys(true);
              keysLoaded = true;
              logBackground(
                "✓ Zero-Knowledge Cloud Vault decrypted and restored successfully.",
              );
            } else if (
              cloudRes.message &&
              cloudRes.message.includes("Incorrect passphrase")
            ) {
              addCommandResult(
                "❌ Incorrect passphrase. Unable to decrypt Zero-Knowledge Cloud Vault.",
                activePeer ?? undefined,
              );
              break;
            } else {
              const cloudExists = await checkCloudVaultExists(name);
              if (cloudExists) {
                addCommandResult(
                  `❌ Cloud vault exists for '${name}', but download failed: ${cloudRes.message}`,
                  activePeer ?? undefined,
                );
                break;
              }
            }
          }

          // 2. Fallback to local encrypted vault if not restored from cloud
          if (!keysLoaded) {
            if (hasVaultConfigured(name)) {
              const vKey = await unlockVault(name, passphrase);
              if (!vKey) {
                addCommandResult(
                  "❌ Incorrect passphrase for local vault.",
                  activePeer ?? undefined,
                );
                break;
              }
              vaultKeyRef.current = vKey;
              setVaultStatus("unlocked");

              const privB64 = await loadPrivateKey(name, vKey);
              if (!privB64) {
                addCommandResult(
                  `❌ No private key found in local vault for '${name}'.`,
                  activePeer ?? undefined,
                );
                break;
              }
              privateKeyRef.current = await importPrivateKey(privB64);
              myPublicKeyB64Ref.current =
                extractPublicKeyFromPkcs8(privB64) ||
                loadPublicKey(name);
              if (myPublicKeyB64Ref.current) {
                savePublicKey(name, myPublicKeyB64Ref.current);
              }

              const spkB64 = await loadSpkPrivate(name, vKey);
              if (spkB64) spkPrivateRef.current = await importPrivateKey(spkB64);
              opksRef.current = await loadOpks(name, vKey);

              sessionPassphraseRef.current = passphrase;
              setHasKeys(true);
              keysLoaded = true;
              logBackground("✓ Local vault unlocked with passphrase.");
            } else {
              addCommandResult(
                `❌ No vault found for '${name}' (neither in Firebase cloud nor locally).\n` +
                  `Please run /register ${name} <passphrase> to create an identity.`,
                activePeer ?? undefined,
              );
              break;
            }
          }

          // 3. Connect to relay server
          const res = await fetch(`${getApiBase()}/api/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: name }),
          });
          const data = await res.json();

          if (!data.success) {
            addCommandResult(
              `Login error from relay: ${data.message}`,
              activePeer ?? undefined,
            );
            break;
          }

          setUsername(data.user.username);
          if (data.user.public_key) {
            myPublicKeyB64Ref.current = data.user.public_key;
          }

          // 4. Authenticate with relay via cryptographic challenge-response
          if (privateKeyRef.current) {
            logBackground("Solving cryptographic challenge from relay...");
            const authRes = await authenticateWithRelay(
              getApiBase(),
              data.user.username,
              privateKeyRef.current,
            );
            if (authRes.success && authRes.token) {
              sessionTokenRef.current = authRes.token;
              saveStoredSessionToken(data.user.username, authRes.token);
            } else {
              addCommandResult(
                `⚠️ Relay challenge authentication failed: ${authRes.error}`,
                activePeer ?? undefined,
              );
            }
          }

          const saved = Array.from(
            new Set([
              ...listSavedPeers(name),
              ...listSavedChatPeers(name),
            ]),
          );
          setContacts(saved);

          authRetryCountRef.current = 0;
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            void sendWsAuth(sessionTokenRef.current || undefined);
          } else {
            connectWs(undefined, true);
          }

          addCommandResult(
            `✓ Logged in as ${data.user.username} [Cryptographically Authenticated].\n` +
              (restoredFromCloud
                ? `☁️ Auto-restored identity, prekeys & chat history from Firebase.\n`
                : `🔒 Local encrypted vault unlocked.\n`) +
              `🔄 Zero-Knowledge auto-sync active.${saved.length > 0 ? ` ${saved.length} contact(s) ready.` : " Use /new <peer> to start a chat."}`,
            activePeer ?? undefined,
          );

          requestSync("login", 3000);
        } catch (err: any) {
          console.error(err);
          addCommandResult(
            `Login failed: ${err?.message || "Failed to reach backend."}`,
            activePeer ?? undefined,
          );
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
  Backend Relay:   ${serverConfigRef.current.apiUrl} [${serverConfigRef.current.source.toUpperCase()}]
  WebSocket:       ${
    wsRef.current?.readyState === WebSocket.OPEN
      ? wsAuthedRef.current
        ? "AUTHENTICATED (ONLINE)"
        : "CONNECTED (NOT AUTHENTICATED)"
      : "DISCONNECTED"
  }
  Relay Status:    ${connStatus.toUpperCase()}
  Screen Shield:   ${screenShield ? "ACTIVE (Anti-Screen Capture)" : "DISABLED"}
  Auto-Lock:       ${autoLockMinutes > 0 ? `${autoLockMinutes} min inactivity` : "OFF"}
  Encryption:      X3DH + Double Ratchet (AES-256-GCM)
  Disappear:       ${disappearMs ? formatDuration(disappearMs) : "off"}`,
          activePeer ?? undefined,
        );
        break;

      case "/clear":
        if (activePeer && username) {
          clearChatHistory(username, activePeer);
          setMessages((prev) =>
            prev.filter(
              (m) =>
                !(
                  m.peer === activePeer &&
                  (m.type === "user" || m.type === "peer") &&
                  !m.isCmdResult
                ),
            ),
          );
          addCommandResult(`Cleared chat history with ${activePeer}.`, activePeer);
        } else {
          setMessages((prev) =>
            prev.filter(
              (m) =>
                (m.type === "user" || m.type === "peer") && !m.isCmdResult,
            ),
          );
          addCommandResult("Console cleared.", undefined);
        }
        break;

      case "/logout":
        if (sessionPassphraseRef.current) {
          void triggerCloudSync("logout");
        }
        if (syncTimeoutRef.current) {
          clearTimeout(syncTimeoutRef.current);
          syncTimeoutRef.current = null;
        }
        sessionPassphraseRef.current = null;
        disappearTimersRef.current.forEach((t) => window.clearTimeout(t));
        disappearTimersRef.current.clear();
        setDisappearMs(null);
        clearStoredSessionToken(username || undefined);
        sessionTokenRef.current = null;
        setUsername(null);
        setActivePeer(null);
        setContacts([]);
        wsAuthedRef.current = false;
        setWsAuthed(false);
        setConnStatus(
          wsRef.current?.readyState === WebSocket.OPEN ? "connected" : "offline",
        );
        setHasKeys(false);
        zeroizeAllKeys();
        addCommandResult("Logged out. Vault locked & in-memory keys purged.", undefined);
        break;

      case "/panic":
        if (syncTimeoutRef.current) {
          clearTimeout(syncTimeoutRef.current);
          syncTimeoutRef.current = null;
        }
        sessionPassphraseRef.current = null;
        executePanic();
        break;

      case "/cloud-backup":
      case "/backup": {
        if (!username || !privateKeyRef.current) {
          addCommandResult(
            "You must be registered or logged in to backup keys.",
            activePeer ?? undefined,
          );
          break;
        }
        let passphrase = parts.slice(1).join(" ").trim();
        if (!passphrase && sessionPassphraseRef.current) {
          passphrase = sessionPassphraseRef.current;
        }
        if (!passphrase) {
          addCommandResult(
            "Usage: /cloud-backup [passphrase]",
            activePeer ?? undefined,
          );
          break;
        }
        if (passphrase.length < 8) {
          addCommandResult(
            "Passphrase must be at least 8 characters for cloud vault security.",
            activePeer ?? undefined,
          );
          break;
        }

        addCommandResult(
          "☁️ Encrypting local keys, chat histories & session ratchets with PBKDF2 (600,000 iterations) + AES-256-GCM...",
          activePeer ?? undefined,
        );

        try {
          const privB64 = await exportPrivateKey(privateKeyRef.current);
          const spkB64 = spkPrivateRef.current
            ? await exportPrivateKey(spkPrivateRef.current)
            : null;

          const allPeers = Array.from(
            new Set([
              ...contacts,
              ...listSavedPeers(username),
              ...listSavedChatPeers(username),
            ]),
          );

          const ratchetsSnapshot: Record<string, any> = {};
          for (const peer of allPeers) {
            const memRatchet = ratchetsByPeerRef.current.get(peer);
            if (memRatchet) {
              try {
                ratchetsSnapshot[peer] = await serializeRatchet(memRatchet);
              } catch {}
            } else {
              const rawSession = localStorage.getItem(
                sessionStorageKey(username, peer),
              );
              if (rawSession) {
                try {
                  const parsed = JSON.parse(rawSession);
                  if (parsed.v === 2 && parsed.enc && vaultKeyRef.current) {
                    const dec = await decryptWithVaultKey(
                      vaultKeyRef.current,
                      parsed.enc,
                    );
                    ratchetsSnapshot[peer] = JSON.parse(dec);
                  } else {
                    ratchetsSnapshot[peer] = parsed;
                  }
                } catch {}
              }
            }
          }

          const historiesSnapshot: Record<string, any> = {};
          for (const peer of allPeers) {
            const msgs = await loadChatHistory(
              username,
              peer,
              vaultKeyRef.current,
            );
            if (msgs && msgs.length > 0) {
              historiesSnapshot[peer] = msgs.map((m) => ({
                id: m.id,
                type: m.type,
                text: m.text,
                timestamp:
                  m.timestamp instanceof Date
                    ? m.timestamp.toISOString()
                    : String(m.timestamp),
                peer: m.peer || peer,
              }));
            }
          }

          const payload: CloudVaultPayload = {
            username,
            privateKeyB64: privB64,
            spkPrivateB64: spkB64,
            opks: opksRef.current,
            contacts: allPeers,
            ratchets: ratchetsSnapshot,
            chatHistories: historiesSnapshot,
            exportedAt: new Date().toISOString(),
          };

          const res = await uploadZeroKnowledgeVault(
            username,
            passphrase,
            payload,
          );
          if (res.success) {
            sessionPassphraseRef.current = passphrase;
            addCommandResult(
              `☁️ ZERO-KNOWLEDGE CLOUD VAULT BACKUP COMPLETE!\n` +
                `────────────────────────────────────────────────────────────\n` +
                `Identity:       ${username}\n` +
                `Contacts:       ${allPeers.length} synced\n` +
                `Chat Histories: ${Object.keys(historiesSnapshot).length} conversations synced\n` +
                `Encryption:     Client-side AES-256-GCM (Zero-Knowledge)\n` +
                `Firebase:       Uploaded to Firestore encrypted_vaults/${username}\n\n` +
                `You can now login from ANY device/browser by running:\n` +
                `   /login ${username} <passphrase>`,
              activePeer ?? undefined,
            );
          } else {
            addCommandResult(
              `❌ Cloud backup failed: ${res.message}`,
              activePeer ?? undefined,
            );
          }
        } catch (err: any) {
          addCommandResult(
            `❌ Backup error: ${err?.message || String(err)}`,
            activePeer ?? undefined,
          );
        }
        break;
      }

      case "/cloud-restore":
      case "/restore": {
        const targetUser = parts[1]?.toLowerCase();
        const passphrase = parts.slice(2).join(" ").trim();
        if (!targetUser || !passphrase) {
          addCommandResult(
            "Usage: /cloud-restore <username> <master_passphrase>",
            activePeer ?? undefined,
          );
          break;
        }
        if (passphrase.length < 8) {
          addCommandResult(
            "Passphrase must be at least 8 characters.",
            activePeer ?? undefined,
          );
          break;
        }

        addCommandResult(
          `☁️ Fetching Zero-Knowledge Cloud Vault for '${targetUser}' from Firebase...`,
          activePeer ?? undefined,
        );

        try {
          const res = await downloadZeroKnowledgeVault(targetUser, passphrase);
          if (!res.success || !res.data) {
            addCommandResult(
              `❌ Cloud restore failed: ${res.message}`,
              activePeer ?? undefined,
            );
            break;
          }

          const vault = res.data;
          const vKey = await setupNewVault(targetUser, passphrase);
          vaultKeyRef.current = vKey;
          setVaultStatus("unlocked");

          await savePrivateKey(
            targetUser,
            vault.privateKeyB64,
            vKey,
          );
          privateKeyRef.current = await importPrivateKey(vault.privateKeyB64);
          myPublicKeyB64Ref.current =
            vault.publicKeyB64 ||
            extractPublicKeyFromPkcs8(vault.privateKeyB64) ||
            loadPublicKey(targetUser);
          if (myPublicKeyB64Ref.current) {
            savePublicKey(targetUser, myPublicKeyB64Ref.current);
          }

          if (vault.spkPrivateB64) {
            await saveSpkPrivate(
              targetUser,
              vault.spkPrivateB64,
              vKey,
            );
            spkPrivateRef.current = await importPrivateKey(
              vault.spkPrivateB64,
            );
          }

          if (Array.isArray(vault.opks)) {
            await saveOpks(targetUser, vault.opks, vKey);
            opksRef.current = vault.opks;
          }

          if (Array.isArray(vault.contacts)) {
            setContacts(vault.contacts);
          }

          if (vault.ratchets && typeof vault.ratchets === "object") {
            for (const [peer, rData] of Object.entries(vault.ratchets)) {
              try {
                const ratchet = await deserializeRatchet(rData);
                ratchetsByPeerRef.current.set(peer, ratchet);
                await saveSession(targetUser, peer, ratchet, vKey);
              } catch {}
            }
          }

          if (vault.chatHistories && typeof vault.chatHistories === "object") {
            for (const [peer, msgs] of Object.entries(vault.chatHistories)) {
              if (Array.isArray(msgs)) {
                const chatMsgs: ChatMessage[] = msgs.map((m: any) => ({
                  id: m.id || crypto.randomUUID(),
                  type: m.type as "user" | "peer",
                  text: m.text,
                  timestamp: new Date(m.timestamp),
                  peer: m.peer || peer,
                }));
                await saveChatHistory(targetUser, peer, chatMsgs, vKey);
              }
            }
          }

          sessionPassphraseRef.current = passphrase;
          setUsername(targetUser);
          setHasKeys(true);

          if (privateKeyRef.current) {
            logBackground("Solving cryptographic challenge from relay after cloud restore...");
            const authRes = await authenticateWithRelay(
              getApiBase(),
              targetUser,
              privateKeyRef.current,
            );
            if (authRes.success && authRes.token) {
              sessionTokenRef.current = authRes.token;
              saveStoredSessionToken(targetUser, authRes.token);
            }
          }

          authRetryCountRef.current = 0;
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            void sendWsAuth(sessionTokenRef.current || undefined);
          } else {
            connectWs(undefined, true);
          }

          addCommandResult(
            `☁️ ZERO-KNOWLEDGE CLOUD VAULT RESTORED SUCCESSFULLY!\n` +
              `────────────────────────────────────────────────────────────\n` +
              `Identity:       ${targetUser}\n` +
              `Private Key:    Decrypted & loaded into device storage\n` +
              `Prekeys:        Restored (${vault.opks?.length || 0} OPKs)\n` +
              `Contacts:       ${vault.contacts?.length || 0} contact(s) restored\n` +
              `Chat Histories: ${Object.keys(vault.chatHistories || {}).length} conversation(s) restored\n\n` +
              `✓ WebSocket authenticated. Ready to chat securely from this device!`,
            activePeer ?? undefined,
          );

          requestSync("restore", 3000);
        } catch (err: any) {
          addCommandResult(
            `❌ Cloud restore error: ${err?.message || String(err)}`,
            activePeer ?? undefined,
          );
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
        } else if (!wsAuthed || connStatus !== "online") {
          addCommandResult(
            "WebSocket not authenticated on relay yet. Run /login or wait for connection.",
            activePeer,
          );
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
                  : connStatus === "connected"
                    ? "text-[#00e5ff] bg-[#00e5ff]/10 border-[#00e5ff]/30"
                    : connStatus === "connecting"
                      ? "text-[#ffb000] bg-[#ffb000]/10 border-[#ffb000]/30"
                      : connStatus === "auth_failed"
                        ? "text-[#ff0055] bg-[#ff0055]/10 border-[#ff0055]/30"
                        : "text-[#ff4444] bg-[#ff4444]/10 border-[#ff4444]/30"
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
              {connStatus === "online"
                ? "ONLINE"
                : connStatus === "connected"
                  ? "CONNECTED (UNAUTHED)"
                  : connStatus === "auth_failed"
                    ? "AUTH FAILED"
                    : connStatus === "connecting"
                      ? "CONNECTING..."
                      : "OFFLINE"}
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
            <button
              onClick={() => setLogOpen((prev) => !prev)}
              className={`text-[11px] px-2.5 py-0.5 rounded border flex items-center gap-1.5 transition-all font-mono ${
                logOpen
                  ? "text-[#00ff41] bg-[#00ff41]/15 border-[#00ff41]/50 shadow-[0_0_8px_rgba(0,255,65,0.2)]"
                  : "text-[#888888] bg-[#111111]/60 border-[#333333] hover:text-[#00ff41] hover:border-[#00ff41]/40"
              }`}
              title={
                activePeer
                  ? logOpen
                    ? "Collapse Console & System Log (or /log)"
                    : "Open Console & System Log (or /log)"
                  : "Console stream active"
              }
            >
              <span>⌨️</span>
              <span>Console</span>
              {consoleMessages.length > 0 && (
                <span
                  className={`text-[9px] px-1.5 py-0.2 rounded-full font-bold ${
                    logOpen
                      ? "bg-[#00ff41]/25 text-[#00ff41]"
                      : "bg-[#222222] text-[#888888]"
                  }`}
                >
                  {consoleMessages.length}
                </span>
              )}
            </button>

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

        {/* Main Area: Split into Chat Stream & Optional Console Drawer */}
        {activePeer ? (
          <div className="flex-1 flex flex-col min-h-0 relative">
            {/* Active Peer Chat Feed (Pure conversation only) */}
            <div className="flex-1 overflow-y-auto px-4 py-3 text-sm leading-relaxed space-y-2 font-mono scroll-smooth select-text min-h-0">
              {chatMessages.length === 0 ? (
                <div className="py-12 flex flex-col items-center justify-center text-center space-y-2 text-xs select-none">
                  <div className="text-[#00e5ff] font-semibold text-sm flex items-center gap-1.5">
                    <span>🔒</span> Secure E2EE Channel Established with {activePeer}
                  </div>
                  <div className="text-[#00551a] max-w-md font-mono">
                    Messages are end-to-end encrypted with X3DH &amp; Double Ratchet with constant-size padding.
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
              ) : (
                chatMessages.map((msg) => (
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
                      {msg.type === "user" ? (
                        <span className="text-[#ffb000] font-semibold text-[11px] px-1.5 py-0.2 rounded bg-[#ffb000]/10 border border-[#ffb000]/30 select-none">
                          you
                        </span>
                      ) : (
                        <span
                          className="text-[#00e5ff] font-semibold text-[11px] px-1.5 py-0.2 rounded bg-[#00e5ff]/10 border border-[#00e5ff]/30 select-none truncate max-w-full text-right"
                          title={msg.peer || activePeer || "peer"}
                        >
                          {msg.peer || activePeer || "peer"}
                        </span>
                      )}
                    </span>

                    {/* Message Content */}
                    <div className="flex-1 min-w-0">
                      {msg.type === "user" ? (
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

            {/* Collapsible Console Drawer when in chat */}
            {logOpen && (
              <div className="h-60 sm:h-64 border-t-2 border-[#004414] bg-[#020b04]/95 backdrop-blur-md flex flex-col shrink-0 shadow-[0_-8px_24px_rgba(0,0,0,0.7)]">
                {/* Console Drawer Header */}
                <div className="px-3 py-1.5 bg-[#031508] border-b border-[#003311] flex items-center justify-between text-xs font-mono select-none">
                  <div className="flex items-center gap-2">
                    <span className="text-[#00ff41] font-bold">&gt;_</span>
                    <span className="text-[#00ff41] font-semibold tracking-wider text-[11px]">
                      CONSOLE &amp; SYSTEM LOG
                    </span>
                    <span className="text-[10px] text-[#00aa2a] bg-[#00220a] border border-[#004414] px-1.5 py-0.2 rounded">
                      {consoleMessages.length} events
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() =>
                        setMessages((prev) =>
                          prev.filter(
                            (m) =>
                              (m.type === "user" || m.type === "peer") &&
                              !m.isCmdResult,
                          ),
                        )
                      }
                      className="text-[10px] text-[#00aa2a] hover:text-[#00ff41] hover:underline px-1 py-0.5"
                      title="Clear console output"
                    >
                      🧹 Clear Log
                    </button>
                    <button
                      onClick={() => setLogOpen(false)}
                      className="text-[11px] text-[#888888] hover:text-[#ff4444] px-1.5 py-0.5 rounded hover:bg-[#200000] transition-colors"
                      title="Collapse console drawer (or /log)"
                    >
                      ✕
                    </button>
                  </div>
                </div>

                {/* Console Drawer Logs List */}
                <div className="flex-1 overflow-y-auto px-4 py-2 text-xs leading-relaxed space-y-1.5 font-mono scroll-smooth select-text bg-[#010803]/80">
                  {consoleMessages.length === 0 ? (
                    <div className="text-[#00551a] italic py-6 text-center text-xs">
                      Console is empty. Run /help or commands to view logs here.
                    </div>
                  ) : (
                    consoleMessages.map((msg) => (
                      <div
                        key={msg.id}
                        className="group flex gap-2 items-start py-0.5 hover:bg-[#041407]/40 px-1 rounded transition-colors"
                      >
                        <span className="text-[#00551a] text-[10px] shrink-0 w-14 pt-0.5 font-mono select-none text-right">
                          {formatTime(msg.timestamp)}
                        </span>
                        <span className="shrink-0 w-12 pt-0.5 flex justify-end">
                          {msg.type === "command" ? (
                            <span className="text-[#c084fc] font-semibold text-[10px] px-1 py-0.2 rounded bg-[#a855f7]/15 border border-[#a855f7]/30 select-none">
                              cmd
                            </span>
                          ) : (
                            <span className="text-[#00ff41] font-semibold text-[10px] px-1 py-0.2 rounded bg-[#00ff41]/10 border border-[#00ff41]/30 select-none">
                              sys
                            </span>
                          )}
                        </span>
                        <div className="flex-1 min-w-0">
                          {msg.type === "command" ? (
                            <div className="text-[#e9d5ff] font-mono text-xs flex items-center gap-1.5">
                              <span className="text-[#a855f7] font-bold select-none">
                                $
                              </span>
                              <span className="font-semibold">{msg.text}</span>
                            </div>
                          ) : (
                            <div className="text-[#99e6aa] text-xs font-mono whitespace-pre-wrap leading-relaxed bg-[#021808]/70 border-l-2 border-[#00ff41]/50 px-2.5 py-1 rounded-r shadow-sm">
                              {msg.text}
                            </div>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                  <div ref={consoleBottomRef} />
                </div>
              </div>
            )}
          </div>
        ) : (
          /* When !activePeer: Main view shows Console stream (register/login/help flow) */
          <div className="flex-1 overflow-y-auto px-4 py-3 text-sm leading-relaxed space-y-2 font-mono scroll-smooth select-text min-h-0">
            {consoleMessages.length === 0 ? (
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
                  Login with{" "}
                  <code className="text-[#00ff66] bg-[#00220a] px-1 py-0.5 rounded border border-[#004414]">
                    /login &lt;user&gt; &lt;passphrase&gt;
                  </code>{" "}
                  or create an identity with{" "}
                  <code className="text-[#00ff66] bg-[#00220a] px-1 py-0.5 rounded border border-[#004414]">
                    /register &lt;user&gt; &lt;passphrase&gt;
                  </code>
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
              <>
                <div className="pb-2 border-b border-[#003311] flex items-center justify-between text-xs text-[#00aa2a] select-none">
                  <span className="flex items-center gap-1.5 font-bold tracking-wider">
                    <span className="text-[#00ff41]">&gt;_</span> CONSOLE &amp; SYSTEM LOG STREAM
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-[#006622]">
                      {consoleMessages.length} events
                    </span>
                    <button
                      onClick={() =>
                        setMessages((prev) =>
                          prev.filter(
                            (m) =>
                              (m.type === "user" || m.type === "peer") &&
                              !m.isCmdResult,
                          ),
                        )
                      }
                      className="text-[10px] text-[#00aa2a] hover:text-[#00ff41] hover:underline"
                    >
                      Clear Console
                    </button>
                  </div>
                </div>
                {consoleMessages.map((msg) => (
                  <div
                    key={msg.id}
                    className="group flex gap-2.5 items-start py-0.5 hover:bg-[#041207]/40 px-2 rounded transition-colors"
                  >
                    {/* Timestamp */}
                    <span className="text-[#00551a] text-[11px] shrink-0 w-16 pt-0.5 font-mono select-none text-right">
                      {formatTime(msg.timestamp)}
                    </span>

                    {/* Sender Badge */}
                    <span className="shrink-0 w-16 pt-0.5 flex justify-end">
                      {msg.type === "command" ? (
                        <span className="text-[#c084fc] font-semibold text-[11px] px-1.5 py-0.2 rounded bg-[#a855f7]/15 border border-[#a855f7]/30 select-none">
                          cmd
                        </span>
                      ) : (
                        <span className="text-[#00ff41] font-semibold text-[11px] px-1.5 py-0.2 rounded bg-[#00ff41]/10 border border-[#00ff41]/30 select-none">
                          sys
                        </span>
                      )}
                    </span>

                    {/* Message Content */}
                    <div className="flex-1 min-w-0">
                      {msg.type === "command" ? (
                        <div className="text-[#e9d5ff] font-mono text-sm flex items-center gap-1.5">
                          <span className="text-[#a855f7] font-bold select-none">
                            $
                          </span>
                          <span className="font-semibold">{msg.text}</span>
                        </div>
                      ) : (
                        <div className="text-[#99e6aa] text-xs font-mono whitespace-pre-wrap leading-relaxed bg-[#021808]/70 border-l-2 border-[#00ff41]/50 px-3 py-1.5 rounded-r shadow-sm">
                          {msg.text}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </>
            )}
            <div ref={consoleBottomRef} />
          </div>
        )}

        {/* Quick Commands Bar above input */}
        <div className="px-4 py-1.5 flex items-center gap-2 overflow-x-auto text-[11px] border-t border-[#00280c] bg-[#020b04] select-none scrollbar-none">
          <span className="text-[#006622] shrink-0 font-semibold tracking-wider text-[10px]">
            QUICK CMDS:
          </span>
          {[
            { label: "/help", cmd: "/help" },
            { label: "/log ⌨️", cmd: "/log" },
            { label: "/verify 🛡️", cmd: "/verify" },
            { label: "/disappear 5m ⏱️", cmd: "/disappear 5m" },
            { label: "/status ⚡", cmd: "/status" },
            { label: "/backup ☁️", cmd: "/cloud-backup" },
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
                : "Type a command e.g. /login <user> <pass>, /register <user> <pass>, /help..."
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
              {connStatus === "online"
                ? "RELAY AUTHENTICATED (ONLINE)"
                : connStatus === "connected"
                  ? "RELAY CONNECTED (NOT AUTHENTICATED)"
                  : connStatus === "auth_failed"
                    ? "RELAY AUTH FAILED"
                    : connStatus === "connecting"
                      ? "RELAY CONNECTING..."
                      : "RELAY OFFLINE"}
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
