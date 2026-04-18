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
