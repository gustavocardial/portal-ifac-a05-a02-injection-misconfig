<?php
/**
 * MISSÃO CORS — Cross-Origin Resource Sharing mal configurado
 * (A02 / CWE-942, CWE-346). A API devolve dados do portal e, em modo
 * vulnerável, autoriza QUALQUER origem a lê-los COM credenciais — então um
 * site malicioso aberto pela vítima consegue ler a resposta autenticada.
 */
require_once __DIR__ . '/../lib/flags.php'; // puxa config (define SECURE) e db

header('Content-Type: application/json; charset=utf-8');

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (SECURE) {
    // ---- Corrigido: libera só a própria origem (allowlist) e nada de "*".
    $selfHost = $_SERVER['HTTP_HOST'] ?? '';
    $permitida = $origin !== '' && parse_url($origin, PHP_URL_HOST) === parse_url('http://' . $selfHost, PHP_URL_HOST);
    if ($permitida) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Vary: Origin');
    }
    // Sem Access-Control-Allow-Credentials com "*".
} else {
    // ---- VULNERÁVEL: reflete a origem (equivale a "*") e ainda com credenciais.
    header('Access-Control-Allow-Origin: ' . ($origin !== '' ? $origin : '*'));
    header('Access-Control-Allow-Credentials: true');
}

$dados = [
    'relatorio' => 'resumo de notas da turma',
    'media_geral' => 7.8,
    'alunos' => 42,
];

if (!SECURE) {
    $dados['_aviso'] = 'CORS permite leitura cross-origin COM credenciais.';
    $dados['flag']   = flags_catalogo()['CORS']['flag'];
}

echo json_encode($dados, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
