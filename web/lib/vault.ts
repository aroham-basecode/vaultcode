export type VaultItemType = 'login';

export type VaultItem = {
  id: string;
  type: VaultItemType;
  title: string;
  username?: string;
  password?: string;
  url?: string;
  host?: string;
  notes?: string;
  createdAt: string;
  updatedAt: string;
};

export type VaultBlobV1 = {
  version: 1;
  updatedAt: string;
  items: VaultItem[];
};

export type EncryptedVaultV1 = {
  version: 1;
  kdf: {
    name: 'scrypt';
    saltB64: string;
    N: number;
    r: number;
    p: number;
    dkLen: number;
  };
  cipher: {
    name: 'xchacha20poly1305';
    nonceB64: string;
  };
  ciphertextB64: string;
};

import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { scrypt } from '@noble/hashes/scrypt.js';
import { randomBytes } from '@noble/hashes/utils.js';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function b64encode(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

function b64decode(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export type VaultCryptoParams = {
  scryptN?: number;
  scryptR?: number;
  scryptP?: number;
  dkLen?: number;
};

export function createEmptyVault(): VaultBlobV1 {
  return { version: 1, updatedAt: new Date().toISOString(), items: [] };
}

export function deriveVaultKey(masterPassword: string, salt: Uint8Array, params?: VaultCryptoParams): Uint8Array {
  const N = params?.scryptN ?? 1 << 16;
  const r = params?.scryptR ?? 8;
  const p = params?.scryptP ?? 1;
  const dkLen = params?.dkLen ?? 32;
  return scrypt(textEncoder.encode(masterPassword), salt, { N, r, p, dkLen });
}

export function encryptVault(vault: VaultBlobV1, masterPassword: string, params?: VaultCryptoParams): EncryptedVaultV1 {
  const salt = randomBytes(16);
  const key = deriveVaultKey(masterPassword, salt, params);
  const nonce = randomBytes(24);

  const plaintext = textEncoder.encode(JSON.stringify(vault));
  const aead = xchacha20poly1305(key, nonce);
  const ciphertext = aead.encrypt(plaintext);

  return {
    version: 1,
    kdf: {
      name: 'scrypt',
      saltB64: b64encode(salt),
      N: params?.scryptN ?? 1 << 16,
      r: params?.scryptR ?? 8,
      p: params?.scryptP ?? 1,
      dkLen: params?.dkLen ?? 32,
    },
    cipher: {
      name: 'xchacha20poly1305',
      nonceB64: b64encode(nonce),
    },
    ciphertextB64: b64encode(ciphertext),
  };
}

export function decryptVault(payload: EncryptedVaultV1, masterPassword: string): VaultBlobV1 {
  if (payload.version !== 1) throw new Error('Unsupported vault payload version');
  if (payload.kdf.name !== 'scrypt') throw new Error('Unsupported KDF');
  if (payload.cipher.name !== 'xchacha20poly1305') throw new Error('Unsupported cipher');

  const salt = b64decode(payload.kdf.saltB64);
  const nonce = b64decode(payload.cipher.nonceB64);
  const ciphertext = b64decode(payload.ciphertextB64);

  const key = scrypt(textEncoder.encode(masterPassword), salt, {
    N: payload.kdf.N,
    r: payload.kdf.r,
    p: payload.kdf.p,
    dkLen: payload.kdf.dkLen,
  });

  const aead = xchacha20poly1305(key, nonce);
  const plaintext = aead.decrypt(ciphertext);
  const json = textDecoder.decode(plaintext);

  const parsed = JSON.parse(json) as VaultBlobV1;
  if (parsed.version !== 1) throw new Error('Unsupported decrypted vault version');
  return parsed;
}
