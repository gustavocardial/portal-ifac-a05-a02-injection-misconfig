<?php
/**
 * Definição das flags (estilo CTF) e registro de pontos no placar — AULA 2.
 *
 * Categorias: OWASP Top 10 2025 — A05 Injection e A02 Security Misconfiguration.
 * Cada vulnerabilidade explorada revela uma flag FLAG{...} enviada em placar.php.
 */
require_once __DIR__ . '/db.php';

function flags_catalogo(): array {
    return [
        // ---------------- A05 — Injection ------------------------------------
        'SQLI_LOGIN' => [
            'flag'   => 'FLAG{sqli_login_bypass_or_1_eq_1}',
            'pontos' => 120,
            'titulo' => 'SQL Injection: bypass de login',
            'cwe'    => 'CWE-89, CWE-564, CWE-943',
            'cat'    => 'A05 Injection',
        ],
        'SQLI_UNION' => [
            'flag'   => 'FLAG{sqli_union_vazou_o_hash}',
            'pontos' => 150,
            'titulo' => 'SQL Injection: UNION extrai dados',
            'cwe'    => 'CWE-89, CWE-200',
            'cat'    => 'A05 Injection',
        ],
        'XSS_REFLECT' => [
            'flag'   => 'FLAG{xss_refletido_na_busca}',
            'pontos' => 100,
            'titulo' => 'XSS refletido na busca',
            'cwe'    => 'CWE-79, CWE-80',
            'cat'    => 'A05 Injection',
        ],
        'XSS_STORED' => [
            'flag'   => 'FLAG{xss_armazenado_no_mural}',
            'pontos' => 130,
            'titulo' => 'XSS armazenado no mural',
            'cwe'    => 'CWE-79, CWE-116',
            'cat'    => 'A05 Injection',
        ],
        'CMDI' => [
            'flag'   => 'FLAG{command_injection_no_ping}',
            'pontos' => 150,
            'titulo' => 'Command Injection no diagnóstico de rede',
            'cwe'    => 'CWE-78, CWE-77',
            'cat'    => 'A05 Injection',
        ],
        'XXE' => [
            'flag'   => 'FLAG{xxe_leu_arquivo_do_servidor}',
            'pontos' => 150,
            'titulo' => 'XXE na importação de notas (XML)',
            'cwe'    => 'CWE-611, CWE-827, CWE-776',
            'cat'    => 'A05 Injection',
        ],
        // ---------------- A02 — Security Misconfiguration --------------------
        'DEFAULTCRED' => [
            'flag'   => 'FLAG{credencial_de_fabrica_no_console}',
            'pontos' => 120,
            'titulo' => 'Credencial de fábrica no console legado',
            'cwe'    => 'CWE-798, CWE-1392, CWE-1188',
            'cat'    => 'A02 Security Misconfiguration',
        ],
        'VERBOSE' => [
            'flag'   => 'FLAG{stack_trace_vazou_segredo}',
            'pontos' => 110,
            'titulo' => 'Erro verboso (stack trace / SQL na tela)',
            'cwe'    => 'CWE-209, CWE-497, CWE-756',
            'cat'    => 'A02 Security Misconfiguration',
        ],
        'DEBUGPARAM' => [
            'flag'   => 'FLAG{modo_debug_exposto}',
            'pontos' => 100,
            'titulo' => 'Modo debug exposto (?debug=1)',
            'cwe'    => 'CWE-489, CWE-16, CWE-215',
            'cat'    => 'A02 Security Misconfiguration',
        ],
        'CORS' => [
            'flag'   => 'FLAG{cors_liberou_geral}',
            'pontos' => 120,
            'titulo' => 'CORS mal configurado na API',
            'cwe'    => 'CWE-942, CWE-346',
            'cat'    => 'A02 Security Misconfiguration',
        ],
        'HEADERS' => [
            'flag'   => 'FLAG{sem_x_frame_options_clickjacking}',
            'pontos' => 90,
            'titulo' => 'Headers de segurança ausentes (clickjacking)',
            'cwe'    => 'CWE-1021, CWE-693, CWE-16',
            'cat'    => 'A02 Security Misconfiguration',
        ],
    ];
}

/** Resolve uma flag enviada -> código da missão (ou null). */
function flag_lookup(string $flag): ?string {
    foreach (flags_catalogo() as $codigo => $info) {
        if (hash_equals($info['flag'], trim($flag))) {
            return $codigo;
        }
    }
    return null;
}

/**
 * Registra a flag para uma equipe/aluno no placar.
 * @return array{ok:bool,msg:string,pontos:int}
 */
function registrar_flag(string $equipe, string $flag): array {
    $equipe = trim($equipe);
    if ($equipe === '') {
        return ['ok' => false, 'msg' => 'Informe seu nome ou o da equipe.', 'pontos' => 0];
    }
    $codigo = flag_lookup($flag);
    if ($codigo === null) {
        return ['ok' => false, 'msg' => 'Flag inválida. Continue explorando!', 'pontos' => 0];
    }
    $info = flags_catalogo()[$codigo];
    try {
        $st = db()->prepare(
            'INSERT INTO placar (equipe, codigo, pontos) VALUES (?, ?, ?)'
        );
        $st->execute([$equipe, $codigo, $info['pontos']]);
    } catch (PDOException $e) {
        return ['ok' => false, 'msg' => 'Você já capturou esta flag: ' . $info['titulo'], 'pontos' => 0];
    }
    return ['ok' => true, 'msg' => 'Flag capturada: ' . $info['titulo'], 'pontos' => $info['pontos']];
}
