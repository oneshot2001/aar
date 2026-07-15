import { CborValue, encodeCbor, equalBytes } from "./cbor";
import { hash } from "./crypto";

export function promotedRoot(leaves: readonly Uint8Array[], nodeDomain: string): Uint8Array {
  if (leaves.length === 0) throw new Error("empty Merkle tree is forbidden");
  let level = [...leaves];
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1];
      next.push(right === undefined ? left : hash(encodeCbor([nodeDomain, left, right])));
    }
    level = next;
  }
  return level[0]!;
}

export function promotedProofWithDomain(leaves: readonly Uint8Array[], index: number, nodeDomain: string): Uint8Array[] {
  if (index < 0 || index >= leaves.length) throw new Error("Merkle leaf index out of range");
  const proof: Uint8Array[] = [];
  let position = index;
  let level = [...leaves];
  while (level.length > 1) {
    const sibling = position % 2 === 0 ? level[position + 1] : level[position - 1];
    if (sibling !== undefined) proof.push(sibling);
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1];
      next.push(right === undefined ? left : hash(encodeCbor([nodeDomain, left, right])));
    }
    position = Math.floor(position / 2);
    level = next;
  }
  return proof;
}

export function verifyPromotedProof(
  leaf: Uint8Array,
  index: number,
  treeSize: number,
  siblings: readonly Uint8Array[],
  nodeDomain: string,
  expectedRoot: Uint8Array,
): boolean {
  let digest = leaf;
  let position = index;
  let width = treeSize;
  let proofIndex = 0;
  while (width > 1) {
    const hasSibling = position % 2 === 1 || position + 1 < width;
    if (hasSibling) {
      const sibling = siblings[proofIndex++];
      if (sibling === undefined) return false;
      digest = position % 2 === 1
        ? hash(encodeCbor([nodeDomain, sibling, digest]))
        : hash(encodeCbor([nodeDomain, digest, sibling]));
    }
    position = Math.floor(position / 2);
    width = Math.ceil(width / 2);
  }
  return proofIndex === siblings.length && equalBytes(digest, expectedRoot);
}

function largestPowerOfTwoLessThan(value: number): number {
  let power = 1;
  while (power * 2 < value) power *= 2;
  return power;
}

export function rfc6962RootFromDigests(leaves: readonly Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return hash(new Uint8Array());
  if (leaves.length === 1) return leaves[0]!;
  const split = largestPowerOfTwoLessThan(leaves.length);
  return hash(Uint8Array.of(1), rfc6962RootFromDigests(leaves.slice(0, split)), rfc6962RootFromDigests(leaves.slice(split)));
}

export function rfc6962Leaf(input: Uint8Array): Uint8Array {
  return hash(Uint8Array.of(0), input);
}

export function rfc6962InclusionProof(leaves: readonly Uint8Array[], index: number): Uint8Array[] {
  if (index < 0 || index >= leaves.length) throw new Error("RFC 6962 leaf index out of range");
  if (leaves.length === 1) return [];
  const split = largestPowerOfTwoLessThan(leaves.length);
  if (index < split) return [...rfc6962InclusionProof(leaves.slice(0, split), index), rfc6962RootFromDigests(leaves.slice(split))];
  return [...rfc6962InclusionProof(leaves.slice(split), index - split), rfc6962RootFromDigests(leaves.slice(0, split))];
}

export function verifyRfc6962Inclusion(
  leaf: Uint8Array,
  index: number,
  treeSize: number,
  proof: readonly Uint8Array[],
  expectedRoot: Uint8Array,
): boolean {
  let digest = leaf;
  let fn = index;
  let sn = treeSize - 1;
  for (const sibling of proof) {
    if ((fn & 1) === 1 || fn === sn) {
      digest = hash(Uint8Array.of(1), sibling, digest);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      digest = hash(Uint8Array.of(1), digest, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && equalBytes(digest, expectedRoot);
}

// The positive KAT uses a power-of-two old tree which has the compact RFC 6962
// proof [MTH(D[old_size:new_size])].
export function rfc6962PowerOfTwoConsistencyProof(leaves: readonly Uint8Array[], oldSize: number): Uint8Array[] {
  if (oldSize <= 0 || oldSize >= leaves.length || (oldSize & (oldSize - 1)) !== 0 || leaves.length !== oldSize * 2) {
    throw new Error("helper requires new_size == 2 * power-of-two old_size");
  }
  return [rfc6962RootFromDigests(leaves.slice(oldSize))];
}

export function verifyPowerOfTwoConsistency(
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  path: readonly Uint8Array[],
): boolean {
  return path.length === 1 && equalBytes(hash(Uint8Array.of(1), oldRoot, path[0]!), newRoot);
}

export function verifyRfc6962Consistency(
  oldSize: number,
  newSize: number,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
  path: readonly Uint8Array[],
): boolean {
  if (oldSize <= 0 || newSize < oldSize) return false;
  if (oldSize === newSize) return path.length === 0 && equalBytes(oldRoot, newRoot);
  let fn = oldSize - 1;
  let sn = newSize - 1;
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }

  let proofIndex = 0;
  let oldDigest: Uint8Array;
  let newDigest: Uint8Array;
  if (fn === 0) {
    oldDigest = oldRoot;
    newDigest = oldRoot;
  } else {
    const first = path[proofIndex++];
    if (first === undefined) return false;
    oldDigest = first;
    newDigest = first;
  }

  while (proofIndex < path.length) {
    const sibling = path[proofIndex++]!;
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      oldDigest = hash(Uint8Array.of(1), sibling, oldDigest);
      newDigest = hash(Uint8Array.of(1), sibling, newDigest);
      while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      newDigest = hash(Uint8Array.of(1), newDigest, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && equalBytes(oldDigest, oldRoot) && equalBytes(newDigest, newRoot);
}
