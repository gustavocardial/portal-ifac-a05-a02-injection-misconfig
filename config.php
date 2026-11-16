<?php
/**
 * ============================================================================
 *  Portal Acadêmico IFAC  —  Laboratório AULA 2
 *  OWASP Top 10 2025 — A05 Injection  +  A02 Security Misconfiguration
 *  Aplicação DELIBERADAMENTE VULNERÁVEL (material didático)
 * ============================================================================
 *
 *  >>> NÃO USE EM PRODUÇÃO. NÃO EXPONHA NA INTERNET. <<<
 *  Rode apenas em rede isolada de laboratório, em máquina descartável.
 *
 *  Este lab reaproveita a mesma mecânica do lab de A01: toggle SECURE,
 *  flags estilo CTF e placar. Cada falha tem dois caminhos no código:
 *
 *      if (SECURE) { ... versão corrigida ... }
 *      else        { ... versão vulnerável (padrão) ... }
 *
 *  SECURE = false -> app vulnerável (modo da aula).  SECURE = true -> mitigado.
 *  Alterne pela constante abaixo (global) ou pelo botão no topo do site
 *  (override por navegador, bom para demonstração lado a lado).
 */

// ---- Toggle padrão (global) -------------------------------------------------
define('SECURE_DEFAULT', false);

// Resolve a constante SECURE já aqui (precisamos dela para definir DEBUG e os
// parâmetros do cookie de sessão mais abaixo).
require_once __DIR__ . '/lib/secure_flag.php';

// ---- Modo DEBUG (parte da lição de A02 Security Misconfiguration) -----------
// Em produção isto JAMAIS deveria ficar ligado. Quando true (e SECURE false),
// erros despejam stack trace, SQL e caminhos na tela (CWE-209/497/756) e o
// parâmetro ?debug=1 passa a revelar dados de configuração (CWE-489).
// No modo SEGURO o debug é forçadamente desligado, não importa o valor aqui.
define('DEBUG_DEFAULT', true);
define('DEBUG', SECURE ? false : DEBUG_DEFAULT);

// ---- Credenciais do banco (padrão do XAMPP: root sem senha) -----------------
define('DB_HOST', getenv('IFAC_DB_HOST') ?: '127.0.0.1');
define('DB_PORT', getenv('IFAC_DB_PORT') ?: '3306');
define('DB_USER', getenv('IFAC_DB_USER') ?: 'root');
define('DB_PASS', getenv('IFAC_DB_PASS') !== false ? getenv('IFAC_DB_PASS') : '');
define('DB_NAME', getenv('IFAC_DB_NAME') ?: 'portal_ifac_aula2');

// ---- Segredo da aplicação (vaza na missão ?debug=1) -------------------------
define('APP_SECRET', 'sup3r_s3cr3t_aula2_injection');

// ---- Caminhos ---------------------------------------------------------------
define('APP_ROOT', __DIR__);
define('UPLOAD_DIR', APP_ROOT . DIRECTORY_SEPARATOR . 'uploads');
define('STORAGE_DIR', APP_ROOT . DIRECTORY_SEPARATOR . 'storage');

// ---- Base URL (ajuste automático) -------------------------------------------
function base_url(): string {
    $dir = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
    foreach (['/admin-legado', '/api'] as $sub) {
        if (str_ends_with($dir, $sub)) {
            $dir = substr($dir, 0, -strlen($sub));
        }
    }
    return rtrim($dir, '/');
}

// ---- Sessão -----------------------------------------------------------------
if (session_status() === PHP_SESSION_NONE) {
    if (SECURE) {
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
    session_start();
}
