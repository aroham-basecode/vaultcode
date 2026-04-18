# Password Manager SaaS (Web + iOS + Android) — Hindi Guide

## 1) Ye project kya hai?
Ye ek **Password Manager SaaS** hai jisme:
- **Web App** (Next.js)
- **Mobile App** (Expo React Native) — iOS + Android
- **Backend API** (NestJS)
- **MySQL Database**

**Most important:** Passwords/entries **client-side encrypt** hote hain. Server par **sirf encrypted data (ciphertext)** store hota hai.

---

## 2) Folder structure (Monorepo)
Project root ke andar:
- `apps/web`  
  Next.js web app
- `apps/api`  
  NestJS backend API
- `apps/mobile`  
  Expo mobile app (iOS/Android)
- `packages/shared`  
  Shared code (types + encryption helpers) — web aur mobile dono use karte hain
- `prisma/schema.prisma`  
  Database schema (Prisma)
- `mysql_schema.sql`  
  MySQL tables banane ke liye SQL (aap remote MySQL par run karoge)

---

## 3) Basic tech samjho (simple language)

### (A) Next.js (Web)
- Web UI banane ke liye React framework.
- `apps/web` se run hota hai.

### (B) Expo (Mobile)
- Ek hi codebase se **Android + iOS** app.
- `apps/mobile` se run hota hai.

### (C) NestJS (Backend API)
- Node.js backend framework.
- Authentication + vault sync endpoints yahin banenge.
- Default port: **4000**

### (D) MySQL
- Users, sessions, vault metadata store.
- Vault content encrypted form me store hota hai.

---

## 4) Encryption / Decryption ka concept (important)

### Goal
- Server ko kabhi bhi real password/secret plain text me nahi milna chahiye.

### Abhi implementation (MVP)
Code `packages/shared/src/vault/crypto.ts` me:
- KDF: **scrypt**
- Cipher: **XChaCha20-Poly1305**

### Flow (simple)
1. User master password enter karta hai (unlock ke time)
2. Client `scrypt` se key derive karta hai (salt + params ke sath)
3. Vault JSON (items list) ko encrypt karta hai
4. API ko encrypted payload bhejta hai
5. DB me encrypted JSON save hota hai

Unlock/reveal ke time:
- Client same master password se key derive karta hai
- Encrypted data decrypt karke password “reveal” karta hai

**Note:** Master password server par store ya send nahi hota.

---

## 5) CSV Import feature (aapka format)
Aapka CSV:

```csv
Title,Host,Username,Password,"Login URL"
MS_Travall,185.161.18.37,admin,Khoor@123,http://185.161.18.37/~travall/admin_asdx02/
```

Import ka logic (UI side) aise hoga:
- CSV parse
- Fields mapping:
  - `title` <= Title
  - `host` <= Host
  - `username` <= Username
  - `password` <= Password
  - `url` <= Login URL
- Items vault me add
- Vault encrypt
- API se sync

---

## 6) MySQL setup (remote)
Docker aapke machine par available nahi tha, isliye humne SQL file banayi:
- `mysql_schema.sql`

Aap remote MySQL par run kar sakte ho:

```bash
mysql -h <HOST> -u <USER> -p < mysql_schema.sql
```

Ye tables create karega:
- `users`
- `vaults`
- `sessions`
- `devices`
- `audit_logs`

---

## 7) Local run ka tareeqa (dev)
### (A) Dependencies install
Root folder me:

```bash
npm install
```

### (B) Web run

```bash
npm run dev:web
```

### (C) API run

```bash
npm run dev:api
```

API default port: `4000`

### (D) Mobile run (Expo)

```bash
npm run dev:mobile
```

Phir:
- Android: Android Studio emulator ya Expo Go
- iOS: Mac par simulator ya Expo Go

---

## 8) API env configuration
`apps/api/.env` me DB URL set hota hai:

```env
DATABASE_URL="mysql://USER:PASSWORD@HOST:3306/password_manager"
PORT=4000
```

Aap remote MySQL ka host/user/pass yahan set karoge.

---

## 9) Common problems (quick help)

### (A) "docker command not found"
- Matlab Docker install nahi hai. Hum remote MySQL use kar rahe hain.

### (B) Encryption related TS error
Agar `@noble/...` module error aaye:
- Ensure `npm install` root par run hua ho.

---

## 10) Next steps (roadmap)
- API me `POST /auth/register` aur `POST /auth/login`
- JWT/session handling
- `GET /vault` (download encrypted)
- `PUT /vault` (upload encrypted)
- Web UI: Unlock + list + reveal + CSV import
- Mobile UI: Unlock + offline cache + sync
