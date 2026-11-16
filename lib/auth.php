<?php
/**
 * Autenticação e autorização (compartilhado pelas páginas).
 * Reaproveitado do lab de A01; aqui o foco das falhas é Injection (A05) e
 * Security Misconfiguration (A02), mas ainda precisamos de login/sessão.
 */
require_once __DIR__ . '/db.php';

function current_user(): ?array {
    if (empty($_SESSION['uid'])) {
        return null;
    }
    $st = db()->prepare('SELECT * FROM usuarios WHERE id = ?');
    $st->execute([$_SESSION['uid']]);
    $u = $st->fetch();
    return $u ?: null;
}

function is_logged_in(): bool {
    return current_user() !== null;
}

function require_login(): array {
    $u = current_user();
    if (!$u) {
        header('Location: ' . base_url() . '/login.php');
        exit;
    }
    return $u;
}

function require_role(string $role): array {
    $u = require_login();
    if ($u['role'] !== $role) {
        http_response_code(403);
        exit('403 — Acesso negado. Este recurso exige o papel: ' . htmlspecialchars($role));
    }
    return $u;
}

function login_user(array $usuario): void {
    session_regenerate_id(true);
    $_SESSION['uid'] = $usuario['id'];
}

function logout_user(): void {
    $_SESSION = [];
    session_destroy();
}

// ---- CSRF (reaproveitado; os formulários de escrita usam o token) -----------

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_field(): string {
    return '<input type="hidden" name="csrf" value="' . csrf_token() . '">';
}

function csrf_check(): bool {
    if (!SECURE) {
        return true;
    }
    $enviado = $_POST['csrf'] ?? '';
    return is_string($enviado) && hash_equals($_SESSION['csrf'] ?? '', $enviado);
}
