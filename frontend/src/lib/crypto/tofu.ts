import { computeSafetyNumber, computeVisualEmojiHash } from "./safety";

export type TofuStatus = "trusted" | "verified" | "mismatch";

export type TofuRecord = {
  peer: string;
  identityKey: string;
  fingerprint: string;
  visualHash: string;
  firstSeen: string;
  status: TofuStatus;
  lastSeen: string;
};

export function getTofuRecord(username: string, peer: string): TofuRecord | null {
  try {
    const raw = localStorage.getItem(`sentinel_tofu_${username}_${peer}`);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function saveTofuRecord(username: string, peer: string, record: TofuRecord) {
  try {
    localStorage.setItem(`sentinel_tofu_${username}_${peer}`, JSON.stringify(record));
  } catch {}
}

export async function checkTofu(
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
