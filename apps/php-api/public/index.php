<?php

declare(strict_types=1);

require dirname(dirname(__DIR__)) . '/config-vault.php';

ini_set('display_errors', '0');
ini_set('log_errors', '1');

$__logDir = dirname(__DIR__) . '/logs';
if (!is_dir($__logDir)) {
  @mkdir($__logDir, 0755, true);
}
$__logFile = $__logDir . '/php-api.log';
ini_set('error_log', $__logFile);

set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
  error_log("PHP ERROR [$severity] $message in $file:$line");
  return false;
});

set_exception_handler(static function (Throwable $e): void {
  error_log('UNCAUGHT EXCEPTION: ' . $e->getMessage() . " in " . $e->getFile() . ':' . $e->getLine());
  error_log($e->getTraceAsString());
  http_response_code(500);
  echo json_encode('Server error', JSON_UNESCAPED_SLASHES);
  exit;
});

register_shutdown_function(static function (): void {
  $err = error_get_last();
  if (!$err) return;

  $fatalTypes = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR];
  if (!in_array($err['type'] ?? 0, $fatalTypes, true)) return;

  error_log('FATAL: ' . ($err['message'] ?? 'Unknown fatal') . ' in ' . ($err['file'] ?? '') . ':' . ($err['line'] ?? 0));
  if (!headers_sent()) {
    header('Content-Type: application/json; charset=utf-8');
    http_response_code(500);
  }
  echo json_encode('Server error', JSON_UNESCAPED_SLASHES);
});

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

function db(): mysqli {
  $dsn = getenv('DATABASE_URL');
  if (!$dsn) fail('DATABASE_URL is not set', 500);

  $parts = parse_url($dsn);
  if (!is_array($parts)) fail('Invalid DATABASE_URL', 500);
  if (($parts['scheme'] ?? '') !== 'mysql') fail('DATABASE_URL must start with mysql://', 500);

  $host = $parts['host'] ?? '';
  $port = (int)($parts['port'] ?? 3306);
  $user = $parts['user'] ?? '';
  $pass = $parts['pass'] ?? '';
  if (strpos($pass, '%') !== false) $pass = rawurldecode($pass);
  $db = isset($parts['path']) ? ltrim($parts['path'], '/') : '';

  if ($host === '' || $user === '' || $db === '') fail('Invalid DATABASE_URL components', 500);

  mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
  $conn = new mysqli($host, $user, $pass, $db, $port);
  $conn->set_charset('utf8mb4');
  return $conn;
}

function db_fetch_one(mysqli $conn, string $sql, string $types, array $params): ?array {
  $stmt = $conn->prepare($sql);
  if ($types !== '') $stmt->bind_param($types, ...$params);
  $stmt->execute();
  $result = $stmt->get_result();
  $row = $result ? $result->fetch_assoc() : null;
  $stmt->close();
  return $row ?: null;
}

function db_exec(mysqli $conn, string $sql, string $types, array $params): void {
  $stmt = $conn->prepare($sql);
  if ($types !== '') $stmt->bind_param($types, ...$params);
  $stmt->execute();
  $stmt->close();
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

function otp_code(): string {
  $n = random_int(0, 999999);
  return str_pad((string)$n, 6, '0', STR_PAD_LEFT);
}

function otp_hash(string $code): string {
  return hash('sha256', $code . jwt_secret());
}

function user_email_verified(mysqli $conn, string $userId): bool {
  $row = db_fetch_one($conn, 'SELECT email_verified_at FROM users WHERE id = ? LIMIT 1', 's', [$userId]);
  if (!$row) return false;
  $v = $row['email_verified_at'] ?? null;
  return $v !== null && (string)$v !== '';
}

function require_verified(mysqli $conn, string $userId): void {
  if (!user_email_verified($conn, $userId)) {
    send_json(['error' => 'Email not verified', 'code' => 'EMAIL_NOT_VERIFIED'], 403);
  }
}

function mail_from(): string {
  $from = getenv('MAIL_FROM');
  if ($from && trim($from) !== '') return trim($from);
  $fallback = getenv('SMTP_USER');
  if ($fallback && trim($fallback) !== '') return trim($fallback);
  return 'no-reply@localhost';
}

function smtp_send(string $to, string $subject, string $body): void {
  $host = (string)(getenv('SMTP_HOST') ?: '');
  $port = (int)(getenv('SMTP_PORT') ?: 587);
  $user = (string)(getenv('SMTP_USER') ?: '');
  $pass = (string)(getenv('SMTP_PASS') ?: '');
  $secure = strtolower((string)(getenv('SMTP_SECURE') ?: 'tls'));

  if ($host === '' || $user === '' || $pass === '') {
    throw new RuntimeException('SMTP is not configured');
  }

  $timeout = 20;
  $fp = fsockopen($host, $port, $errno, $errstr, $timeout);
  if (!$fp) throw new RuntimeException("SMTP connect failed: $errstr ($errno)");
  stream_set_timeout($fp, $timeout);

  $read = static function () use ($fp): string {
    $data = '';
    while (!feof($fp)) {
      $line = fgets($fp, 515);
      if ($line === false) break;
      $data .= $line;
      if (strlen($line) >= 4 && $line[3] === ' ') break;
    }
    return $data;
  };

  $expect = static function (string $resp, array $codes): void {
    $code = (int)substr($resp, 0, 3);
    if (!in_array($code, $codes, true)) {
      throw new RuntimeException('SMTP error: ' . trim($resp));
    }
  };

  $write = static function (string $cmd) use ($fp): void {
    fwrite($fp, $cmd . "\r\n");
  };

  $greeting = $read();
  $expect($greeting, [220]);

  $name = (string)(getenv('SMTP_HELO') ?: ($_SERVER['SERVER_NAME'] ?? 'localhost'));
  $write('EHLO ' . $name);
  $ehlo = $read();
  if (substr($ehlo, 0, 3) !== '250') {
    $write('HELO ' . $name);
    $helo = $read();
    $expect($helo, [250]);
    $ehlo = $helo;
  }

  if ($secure === 'tls') {
    $write('STARTTLS');
    $tls = $read();
    $expect($tls, [220]);
    if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
      throw new RuntimeException('SMTP STARTTLS failed');
    }
    $write('EHLO ' . $name);
    $ehlo2 = $read();
    $expect($ehlo2, [250]);
  }

  $write('AUTH LOGIN');
  $a1 = $read();
  $expect($a1, [334]);
  $write(base64_encode($user));
  $a2 = $read();
  $expect($a2, [334]);
  $write(base64_encode($pass));
  $a3 = $read();
  $expect($a3, [235]);

  $from = mail_from();
  $write('MAIL FROM:<' . $from . '>');
  $m1 = $read();
  $expect($m1, [250]);
  $write('RCPT TO:<' . $to . '>');
  $m2 = $read();
  $expect($m2, [250, 251]);
  $write('DATA');
  $d1 = $read();
  $expect($d1, [354]);

  $headers = [];
  $headers[] = 'From: ' . $from;
  $headers[] = 'To: ' . $to;
  $headers[] = 'Subject: ' . $subject;
  $headers[] = 'MIME-Version: 1.0';
  $headers[] = 'Content-Type: text/plain; charset=utf-8';
  $msg = implode("\r\n", $headers) . "\r\n\r\n" . $body;
  $msg = str_replace(["\r\n.", "\n."], ["\r\n..", "\n.."], $msg);
  $write($msg . "\r\n.");
  $d2 = $read();
  $expect($d2, [250]);

  $write('QUIT');
  fclose($fp);
}

function send_email(string $to, string $subject, string $body): void {
  try {
    if (getenv('SMTP_HOST')) {
      smtp_send($to, $subject, $body);
      return;
    }
  } catch (Throwable $e) {
    error_log('EMAIL SMTP FAILED: ' . $e->getMessage());
  }

  $headers = 'From: ' . mail_from() . "\r\n" . 'Content-Type: text/plain; charset=utf-8';
  $ok = @mail($to, $subject, $body, $headers);
  if (!$ok) {
    throw new RuntimeException('Email send failed');
  }
}

function send_otp_email(string $email, string $otp, string $purpose): void {
  $app = (string)(getenv('APP_NAME') ?: 'VaultCode');
  $ttl = (int)(getenv('OTP_TTL_SECONDS') ?: 600);

  if ($purpose === 'verify_email') {
    $subject = $app . ' verification code';
    $body = "Your verification code is: $otp\n\nThis code expires in " . (int)ceil($ttl / 60) . " minutes.";
  } else {
    $subject = $app . ' password reset code';
    $body = "Your password reset code is: $otp\n\nThis code expires in " . (int)ceil($ttl / 60) . " minutes.";
  }

  send_email($email, $subject, $body);
}

function create_otp(mysqli $conn, string $userId, string $purpose, int $ttlSeconds = 600): string {
  $code = otp_code();
  $hash = otp_hash($code);
  $id = nanoid32();
  db_exec(
    $conn,
    'INSERT INTO auth_otps (id, user_id, purpose, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(3), INTERVAL ? SECOND), NOW(3))',
    'ssssi',
    [$id, $userId, $purpose, $hash, $ttlSeconds],
  );
  return $code;
}

function consume_otp(mysqli $conn, string $userId, string $purpose, string $code): void {
  $row = db_fetch_one(
    $conn,
    'SELECT id, code_hash FROM auth_otps WHERE user_id = ? AND purpose = ? AND used_at IS NULL AND expires_at > NOW(3) ORDER BY created_at DESC LIMIT 1',
    'ss',
    [$userId, $purpose],
  );
  if (!$row) fail('Invalid or expired code', 400);
  $expected = (string)($row['code_hash'] ?? '');
  $actual = otp_hash($code);
  if (!hash_equals($expected, $actual)) fail('Invalid or expired code', 400);
  db_exec($conn, 'UPDATE auth_otps SET used_at = NOW(3) WHERE id = ?', 's', [(string)$row['id']]);
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
if (substr($path, 0, strlen($prefix)) === $prefix) {
  $path = substr($path, strlen($prefix));
}
if ($path === '') $path = '/';

try {
  
  if ($method == 'POST' && $path == '/auth/register') {
    $body = json_body();
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $password = (string)($body['password'] ?? '');
    if ($email === '' || $password === '') fail('Email and password required', 400);

    $conn = db();

    $existing = db_fetch_one($conn, 'SELECT id, email FROM users WHERE email = ? LIMIT 1', 's', [$email]);
    if ($existing) fail('Email already registered', 409);

    $userId = nanoid32();
    $hash = password_hash($password, PASSWORD_BCRYPT);
    if ($hash === false) fail('Failed to hash password', 500);

    db_exec(
      $conn,
      'INSERT INTO users (id, email, password_hash, email_verified_at, created_at, updated_at) VALUES (?, ?, ?, NULL, NOW(3), NOW(3))',
      'sss',
      [$userId, $email, $hash],
    );

    $otp = create_otp($conn, $userId, 'verify_email');
    send_otp_email($email, $otp, 'verify_email');
    $res = ['user' => ['id' => $userId, 'email' => $email], 'requiresVerification' => true];
    $debug = getenv('DEBUG');
    if ($debug === '1' || strtolower((string)$debug) === 'true') {
      $res['otp'] = $otp;
    }
    send_json($res);
  }

  if ($method === 'POST' && $path === '/auth/verify-email') {
    $body = json_body();
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $code = trim((string)($body['code'] ?? ''));
    if ($email === '' || $code === '') fail('Email and code required', 400);
    $conn = db();
    $user = db_fetch_one($conn, 'SELECT id, email FROM users WHERE email = ? LIMIT 1', 's', [$email]);
    if (!$user) fail('Invalid code', 400);
    $userId = (string)$user['id'];
    consume_otp($conn, $userId, 'verify_email', $code);
    db_exec($conn, 'UPDATE users SET email_verified_at = NOW(3), updated_at = NOW(3) WHERE id = ?', 's', [$userId]);
    $token = jwt_sign(['sub' => $userId, 'email' => (string)$user['email']]);
    send_json(['user' => ['id' => $userId, 'email' => (string)$user['email']], 'token' => $token]);
  }

  if ($method === 'POST' && $path === '/auth/resend-code') {
    $body = json_body();
    $email = strtolower(trim((string)($body['email'] ?? '')));
    if ($email === '') fail('Email required', 400);
    $conn = db();
    $user = db_fetch_one($conn, 'SELECT id, email, email_verified_at FROM users WHERE email = ? LIMIT 1', 's', [$email]);
    if (!$user) fail('Invalid email', 400);
    if (($user['email_verified_at'] ?? null) !== null && (string)($user['email_verified_at'] ?? '') !== '') {
      send_json(['sent' => false]);
    }
    $otp = create_otp($conn, (string)$user['id'], 'verify_email');
    send_otp_email($email, $otp, 'verify_email');
    $res = ['sent' => true];
    $debug = getenv('DEBUG');
    if ($debug === '1' || strtolower((string)$debug) === 'true') {
      $res['otp'] = $otp;
    }
    send_json($res);
  }

  if ($method === 'POST' && $path === '/auth/forgot-password') {
    $body = json_body();
    $email = strtolower(trim((string)($body['email'] ?? '')));
    if ($email === '') fail('Email required', 400);
    $conn = db();
    $user = db_fetch_one($conn, 'SELECT id FROM users WHERE email = ? LIMIT 1', 's', [$email]);
    if (!$user) send_json(['sent' => true]);
    $otp = create_otp($conn, (string)$user['id'], 'reset_password');
    send_otp_email($email, $otp, 'reset_password');
    $res = ['sent' => true];
    $debug = getenv('DEBUG');
    if ($debug === '1' || strtolower((string)$debug) === 'true') {
      $res['otp'] = $otp;
    }
    send_json($res);
  }

  if ($method === 'POST' && $path === '/auth/reset-password') {
    $body = json_body();
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $code = trim((string)($body['code'] ?? ''));
    $newPassword = (string)($body['newPassword'] ?? '');
    if ($email === '' || $code === '' || $newPassword === '') fail('Email, code and newPassword required', 400);
    $conn = db();
    $user = db_fetch_one($conn, 'SELECT id, email FROM users WHERE email = ? LIMIT 1', 's', [$email]);
    if (!$user) fail('Invalid code', 400);
    $userId = (string)$user['id'];
    consume_otp($conn, $userId, 'reset_password', $code);
    $hash = password_hash($newPassword, PASSWORD_BCRYPT);
    if ($hash === false) fail('Failed to hash password', 500);
    db_exec($conn, 'UPDATE users SET password_hash = ?, updated_at = NOW(3) WHERE id = ?', 'ss', [$hash, $userId]);
    $token = jwt_sign(['sub' => $userId, 'email' => (string)$user['email']]);
    send_json(['user' => ['id' => $userId, 'email' => (string)$user['email']], 'token' => $token]);
  }

  if ($method === 'POST' && $path === '/auth/login') {
    $body = json_body();
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $password = (string)($body['password'] ?? '');
    if ($email === '' || $password === '') fail('Email and password required', 400);

    $conn = db();

    $user = db_fetch_one($conn, 'SELECT id, email, password_hash, email_verified_at FROM users WHERE email = ? LIMIT 1', 's', [$email]);
    if (!$user) fail('Invalid credentials', 401);

    $ok = password_verify($password, (string)($user['password_hash'] ?? ''));
    if (!$ok) fail('Invalid credentials', 401);

    if (($user['email_verified_at'] ?? null) === null || (string)($user['email_verified_at'] ?? '') === '') {
      send_json(['error' => 'Email not verified', 'code' => 'EMAIL_NOT_VERIFIED'], 403);
    }

    $token = jwt_sign(['sub' => (string)$user['id'], 'email' => (string)$user['email']]);
    send_json(['user' => ['id' => (string)$user['id'], 'email' => (string)$user['email']], 'token' => $token]);
  }

  if ($path === '/vault' && ($method === 'GET' || $method === 'PUT')) {
    $u = auth_user();
    $userId = $u['userId'];

    $conn = db();

    require_verified($conn, $userId);

    if ($method === 'GET') {
      $row = db_fetch_one(
        $conn,
        'SELECT encrypted_vault AS encryptedVault, version, created_at AS createdAt, updated_at AS updatedAt FROM vaults WHERE user_id = ? LIMIT 1',
        's',
        [$userId],
      );
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

      $existing = db_fetch_one($conn, 'SELECT id FROM vaults WHERE user_id = ? LIMIT 1', 's', [$userId]);

      if ($existing) {
        if ($version === null) {
          db_exec($conn, 'UPDATE vaults SET encrypted_vault = ?, updated_at = NOW(3) WHERE user_id = ?', 'ss', [$encJson, $userId]);
        } else {
          $v = (int)$version;
          db_exec(
            $conn,
            'UPDATE vaults SET encrypted_vault = ?, version = ?, updated_at = NOW(3) WHERE user_id = ?',
            'sis',
            [$encJson, $v, $userId],
          );
        }
      } else {
        $v = $version === null ? 1 : (int)$version;
        db_exec(
          $conn,
          'INSERT INTO vaults (id, user_id, encrypted_vault, version, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(3), NOW(3))',
          'sssi',
          [$vaultId, $userId, $encJson, $v],
        );
      }

      $row = db_fetch_one(
        $conn,
        'SELECT encrypted_vault AS encryptedVault, version, created_at AS createdAt, updated_at AS updatedAt FROM vaults WHERE user_id = ? LIMIT 1',
        's',
        [$userId],
      );
      if (!$row) send_json(null);
      $row['encryptedVault'] = json_decode((string)$row['encryptedVault'], true);
      send_json($row);
    }
  }

  fail('Not found', 404);
} catch (Throwable $e) {
  error_log('CAUGHT EXCEPTION: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
  error_log($e->getTraceAsString());

  $debug = getenv('DEBUG');
  if ($debug === '1' || strtolower((string)$debug) === 'true') {
    send_json(
      [
        'error' => 'Server error',
        'message' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine(),
      ],
      500,
    );
  }

  fail('Server error', 500);
}
