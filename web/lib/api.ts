export type AuthResponse = {
  user: { id: string; email: string };
  token: string;
};

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(text || `Request failed: ${res.status}`);
  }

  return (await res.json()) as T;
}

export async function apiRegister(email: string, password: string): Promise<AuthResponse> {
  return jsonFetch<AuthResponse>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function apiLogin(email: string, password: string): Promise<AuthResponse> {
  return jsonFetch<AuthResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export type VaultRecord = {
  encryptedVault: unknown;
  version: number;
  updatedAt: string;
  createdAt: string;
} | null;

export async function apiGetVault(token: string): Promise<VaultRecord> {
  return jsonFetch<VaultRecord>('/vault', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

export async function apiPutVault(token: string, encryptedVault: unknown, version?: number): Promise<VaultRecord> {
  return jsonFetch<VaultRecord>('/vault', {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ encryptedVault, version }),
  });
}

export async function apiForgotPassword(email: string): Promise<{ sent: boolean }> {
  return jsonFetch<{ sent: boolean }>('/auth/forgot-password', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
}

export async function apiResetPassword(email: string, code: string, newPassword: string): Promise<AuthResponse> {
  return jsonFetch<AuthResponse>('/auth/reset-password', {
    method: 'POST',
    body: JSON.stringify({ email, code, newPassword }),
  });
}
