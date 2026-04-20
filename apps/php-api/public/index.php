<?php

declare(strict_types=1);

require __DIR__ . '/../../config-vault.php';

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: ' . (getenv('CORS_ORIGIN') ?: '*'));
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  http_response_code(204);
  exit;
}

function json_body(): array {
  $raw = file_get_contents('php://input');
  if ($raw === false || trim($raw) === '') return [];
  $data = json_decode($raw, true);
  return is_array($data) ? $data : [];
}

function send_json($data, int $status = 200): void {
  http_response_code($status);
  echo json_encode($data, JSON_UNESCAPED_SLASHES);
  exit;
}

function fail(string $message, int $status): void {
  send_json($message, $status);
}

function db(): PDO {
  $dsn = getenv('DATABASE_URL');
  if (!$dsn) fail('DATABASE_URL is not set', 500);

  $parts = parse_url($dsn);
  if (!is_array($parts)) fail('Invalid DATABASE_URL', 500);
  if (($parts['scheme'] ?? '') !== 'mysql') fail('DATABASE_URL must start with mysql://', 500);

  $host = $parts['host'] ?? '';
  $port = (int)($parts['port'] ?? 3306);
  $user = $parts['user'] ?? '';
  $pass = $parts['pass'] ?? '';
  $db = isset($parts['path']) ? ltrim($parts['path'], '/') : '';

  if ($host === '' || $user === '' || $db === '') fail('Invalid DATABASE_URL components', 500);

  $pdo = new PDO(
    sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $host, $port, $db),
    $user,
    $pass,
    [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]
  );

  return $pdo;
}

function nanoid32(): string {
  $alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
  $bytes = random_bytes(32);
  $out = '';
  for ($i = 0; $i < 32; $i++) {
    $out .= $alphabet[ord($bytes[$i]) % 36];
  }
  return $out;
}

function b64url_encode(string $data): string {
  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function b64url_decode(string $data): string {
  $remainder = strlen($data) % 4;
  if ($remainder) $data .= str_repeat('=', 4 - $remainder);
  $decoded = base64_decode(strtr($data, '-_', '+/'), true);
  return $decoded === false ? '' : $decoded;
}

function jwt_secret(): string {
  $secret = getenv('JWT_SECRET');
  if (!$secret) fail('JWT_SECRET is not set', 500);
  return $secret;
}

function jwt_sign(array $payload, int $ttlSeconds = 604800): string {
  $now = time();
  $header = ['alg' => 'HS256', 'typ' => 'JWT'];
  $payload['iat'] = $now;
  $payload['exp'] = $now + $ttlSeconds;

  $h = b64url_encode(json_encode($header, JSON_UNESCAPED_SLASHES));
  $p = b64url_encode(json_encode($payload, JSON_UNESCAPED_SLASHES));
  $sig = hash_hmac('sha256', "$h.$p", jwt_secret(), true);
  $s = b64url_encode($sig);
  return "$h.$p.$s";
}

function jwt_verify(string $token): array {
  $parts = explode('.', $token);
  if (count($parts) !== 3) fail('Unauthorized', 401);

  [$h, $p, $s] = $parts;
  $sig = b64url_decode($s);
  if ($sig === '') fail('Unauthorized', 401);

  $expected = hash_hmac('sha256', "$h.$p", jwt_secret(), true);
  if (!hash_equals($expected, $sig)) fail('Unauthorized', 401);

  $payload = json_decode(b64url_decode($p), true);
  if (!is_array($payload)) fail('Unauthorized', 401);

  $exp = (int)($payload['exp'] ?? 0);
  if ($exp !== 0 && time() >= $exp) fail('Unauthorized', 401);

  return $payload;
}

function auth_user(): array {
  $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
  if (!preg_match('/^Bearer\s+(.+)$/i', $auth, $m)) fail('Unauthorized', 401);
  $payload = jwt_verify(trim($m[1]));

  $sub = $payload['sub'] ?? null;
  $email = $payload['email'] ?? null;
  if (!is_string($sub) || $sub === '' || !is_string($email) || $email === '') fail('Unauthorized', 401);

  return ['userId' => $sub, 'email' => $email];
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = rtrim($path, '/');
if ($path === '') $path = '/';
$prefix = '/vault';
if (str_starts_with($path, $prefix)) $path = substr($path, strlen($prefix));
if ($path === '') $path = '/';

try {
  if ($method === 'POST' && $path === '/auth/register') {
    $body = json_body();
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $password = (string)($body['password'] ?? '');
    if ($email === '' || $password === '') fail('Email and password required', 400);

    $pdo = db();

    $stmt = $pdo->prepare('SELECT id, email FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    $existing = $stmt->fetch();
    if ($existing) fail('Email already registered', 409);

    $userId = nanoid32();
    $hash = password_hash($password, PASSWORD_BCRYPT);
    if ($hash === false) fail('Failed to hash password', 500);

    $stmt = $pdo->prepare('INSERT INTO users (id, email, password_hash, created_at, updated_at) VALUES (?, ?, ?, NOW(3), NOW(3))');
    $stmt->execute([$userId, $email, $hash]);

    $token = jwt_sign(['sub' => $userId, 'email' => $email]);
    send_json(['user' => ['id' => $userId, 'email' => $email], 'token' => $token]);
  }

  if ($method === 'POST' && $path === '/auth/login') {
    $body = json_body();
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $password = (string)($body['password'] ?? '');
    if ($email === '' || $password === '') fail('Email and password required', 400);

    $pdo = db();

    $stmt = $pdo->prepare('SELECT id, email, password_hash FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    $user = $stmt->fetch();
    if (!$user) fail('Invalid credentials', 401);

    $ok = password_verify($password, (string)$user['password_hash']);
    if (!$ok) fail('Invalid credentials', 401);

    $token = jwt_sign(['sub' => (string)$user['id'], 'email' => (string)$user['email']]);
    send_json(['user' => ['id' => (string)$user['id'], 'email' => (string)$user['email']], 'token' => $token]);
  }

  if ($path === '/vault' && ($method === 'GET' || $method === 'PUT')) {
    $u = auth_user();
    $userId = $u['userId'];

    $pdo = db();

    if ($method === 'GET') {
      $stmt = $pdo->prepare('SELECT encrypted_vault AS encryptedVault, version, created_at AS createdAt, updated_at AS updatedAt FROM vaults WHERE user_id = ? LIMIT 1');
      $stmt->execute([$userId]);
      $row = $stmt->fetch();
      if (!$row) send_json(null);

      $row['encryptedVault'] = json_decode((string)$row['encryptedVault'], true);
      send_json($row);
    }

    if ($method === 'PUT') {
      $body = json_body();
      $encryptedVault = $body['encryptedVault'] ?? null;
      $version = $body['version'] ?? null;

      if ($encryptedVault === null) fail('encryptedVault required', 400);
      $encJson = json_encode($encryptedVault, JSON_UNESCAPED_SLASHES);
      if ($encJson === false) fail('Invalid encryptedVault', 400);

      $vaultId = nanoid32();

      $stmt = $pdo->prepare('SELECT id FROM vaults WHERE user_id = ? LIMIT 1');
      $stmt->execute([$userId]);
      $existing = $stmt->fetch();

      if ($existing) {
        if ($version === null) {
          $stmt = $pdo->prepare('UPDATE vaults SET encrypted_vault = ?, updated_at = NOW(3) WHERE user_id = ?');
          $stmt->execute([$encJson, $userId]);
        } else {
          $stmt = $pdo->prepare('UPDATE vaults SET encrypted_vault = ?, version = ?, updated_at = NOW(3) WHERE user_id = ?');
          $stmt->execute([$encJson, (int)$version, $userId]);
        }
      } else {
        $v = $version === null ? 1 : (int)$version;
        $stmt = $pdo->prepare('INSERT INTO vaults (id, user_id, encrypted_vault, version, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(3), NOW(3))');
        $stmt->execute([$vaultId, $userId, $encJson, $v]);
      }

      $stmt = $pdo->prepare('SELECT encrypted_vault AS encryptedVault, version, created_at AS createdAt, updated_at AS updatedAt FROM vaults WHERE user_id = ? LIMIT 1');
      $stmt->execute([$userId]);
      $row = $stmt->fetch();
      if (!$row) send_json(null);
      $row['encryptedVault'] = json_decode((string)$row['encryptedVault'], true);
      send_json($row);
    }
  }

  fail('Not found', 404);
} catch (Throwable $e) {
  fail('Server error', 500);
}
