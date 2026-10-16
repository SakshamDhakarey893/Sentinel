import QRCode from "qrcode";

export const EMOJI_FINGERPRINT_POOL = [
  "🛡️", "⚡", "🔒", "🔑", "🛰️", "🛸", "💎", "🔮",
  "🧬", "🌌", "⚓", "⚔️", "👁️", "🎯", "🔥", "🪐",
];

export async function computeSafetyNumber(
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

export async function computeVisualEmojiHash(safetyNumber: string): Promise<string> {
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

export async function generateTerminalQr(
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
