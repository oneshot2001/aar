declare module "bun:test" {
  export function describe(name: string, body: () => void): void;
  export function test(name: string, body: () => void | Promise<void>, timeout?: number): void;
  export function expect(value: unknown, message?: string): {
    toBe(expected: unknown): void;
    toEqual(expected: unknown): void;
  };
}

declare module "node:fs/promises" {
  export function mkdir(path: string, options?: { recursive?: boolean }): Promise<unknown>;
  export function readdir(path: string): Promise<string[]>;
  export function rm(path: string): Promise<void>;
  export function writeFile(path: string, data: Uint8Array | string): Promise<void>;
}

declare module "node:fs" {
  export function readFileSync(path: string): Uint8Array;
  export function readFileSync(path: string, encoding: "utf8"): string;
}

declare module "node:path" {
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
}

declare module "node:url" {
  export function fileURLToPath(url: string | URL): string;
}
