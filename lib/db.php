<?php
/**
 * Conexão PDO com o MySQL/MariaDB do XAMPP.
 * Reaproveitada por todas as páginas e pelo instalador.
 */
require_once __DIR__ . '/../config.php';

function db(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
        DB_HOST, DB_PORT, DB_NAME);
    try {
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    } catch (PDOException $e) {
        // Vazamento de informação (CWE-497 / CWE-200): em modo vulnerável
        // despejamos o erro cru do banco na tela. Corrigido -> mensagem genérica.
        if (SECURE) {
            http_response_code(500);
            exit('Erro ao conectar ao banco de dados. Procure o administrador.');
        }
        http_response_code(500);
        exit('<pre>Falha de conexão PDO: ' . $e->getMessage()
            . "\nDSN: $dsn\nUsuário: " . DB_USER
            . "\n\nDica: rode o instalador em install.php</pre>");
    }
    return $pdo;
}

/** Conexão SEM selecionar banco — usada só pelo instalador para criar o schema. */
function db_server(): PDO {
    $dsn = sprintf('mysql:host=%s;port=%s;charset=utf8mb4', DB_HOST, DB_PORT);
    return new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
}
