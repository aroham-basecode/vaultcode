export type PendingCredential = {
  host: string;
  url: string;
  title?: string;
  username?: string;
  password?: string;
  createdAt: string;
};

export type StoredConfig = {
  apiBase: string;
  token: string;
};
