import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { p256 } from "@noble/curves/nist.js";
import { fromHex, toHex } from "../../harness/cbor";
import { hash } from "../../harness/crypto";

export const DEMO_KEY_ROLES = ["agent", "ep", "authority", "outcome", "anchor", "verifier-trust"] as const;
export type DemoKeyRole = typeof DEMO_KEY_ROLES[number];

const P256_SPKI_PREFIX = fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");

export interface DemoKey {
  readonly role: DemoKeyRole;
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly spki: Uint8Array;
  readonly kid: Uint8Array;
}

interface StoredPrivateKey {
  version: 1;
  role: DemoKeyRole;
  private_key: string;
  public_key: string;
  spki: string;
  kid: string;
}

export interface StoredPublicKey {
  version: 1;
  role: DemoKeyRole;
  spki: string;
  kid: string;
}

function keyFromPrivate(role: DemoKeyRole, privateKey: Uint8Array): DemoKey {
  const publicKey = p256.getPublicKey(privateKey, false);
  const spki = new Uint8Array(P256_SPKI_PREFIX.length + publicKey.length);
  spki.set(P256_SPKI_PREFIX);
  spki.set(publicKey, P256_SPKI_PREFIX.length);
  return { role, privateKey, publicKey, spki, kid: hash(spki) };
}

export async function generateDemoKeys(privateDirectory: string, publicOutput?: string): Promise<Readonly<Record<DemoKeyRole, DemoKey>>> {
  await mkdir(privateDirectory, { recursive: true, mode: 0o700 });
  await chmod(privateDirectory, 0o700);
  const entries: Array<[DemoKeyRole, DemoKey]> = [];
  for (const role of DEMO_KEY_ROLES) {
    const { secretKey } = p256.keygen();
    const key = keyFromPrivate(role, secretKey);
    const stored: StoredPrivateKey = {
      version: 1,
      role,
      private_key: toHex(key.privateKey),
      public_key: toHex(key.publicKey),
      spki: toHex(key.spki),
      kid: toHex(key.kid),
    };
    const path = join(privateDirectory, `${role}.private.json`);
    await writeFile(path, `${JSON.stringify(stored, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    await chmod(path, 0o600);
    entries.push([role, key]);
  }
  if (publicOutput) {
    const publicKeys: StoredPublicKey[] = entries.map(([role, key]) => ({
      version: 1,
      role,
      spki: toHex(key.spki),
      kid: toHex(key.kid),
    }));
    await mkdir(dirname(publicOutput), { recursive: true });
    await writeFile(publicOutput, `${JSON.stringify({ version: 1, keys: publicKeys }, null, 2)}\n`);
  }
  return Object.fromEntries(entries) as Record<DemoKeyRole, DemoKey>;
}

export async function loadDemoKeys(privateDirectory: string): Promise<Readonly<Record<DemoKeyRole, DemoKey>>> {
  const entries: Array<[DemoKeyRole, DemoKey]> = [];
  for (const role of DEMO_KEY_ROLES) {
    const source = JSON.parse(await readFile(join(privateDirectory, `${role}.private.json`), "utf8")) as StoredPrivateKey;
    if (source.version !== 1 || source.role !== role) throw new Error(`invalid demo key file for ${role}`);
    const key = keyFromPrivate(role, fromHex(source.private_key));
    if (toHex(key.kid) !== source.kid || toHex(key.spki) !== source.spki || toHex(key.publicKey) !== source.public_key) {
      throw new Error(`demo key integrity check failed for ${role}`);
    }
    entries.push([role, key]);
  }
  const keys = Object.fromEntries(entries) as Record<DemoKeyRole, DemoKey>;
  const kids = new Set(DEMO_KEY_ROLES.map((role) => toHex(keys[role].kid)));
  if (kids.size !== DEMO_KEY_ROLES.length) throw new Error("demo roles must use distinct keys");
  return keys;
}
