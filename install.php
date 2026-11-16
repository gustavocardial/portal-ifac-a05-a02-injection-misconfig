<?php
/**
 * Instalador de 1 clique — AULA 2 (A05 Injection + A02 Security Misconfiguration).
 * Cria banco, tabelas, seed e os arquivos-alvo das missões (XXE, Command Injection).
 * Abra:  http://localhost/aula02/install.php
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/flags.php';

$log = []; $erro = null;

try {
    $srv = db_server();
    $srv->exec('CREATE DATABASE IF NOT EXISTS `' . DB_NAME . '` '
        . 'CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    $log[] = 'Banco `' . DB_NAME . '` pronto.';

    $pdo = db();
    $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
    foreach (['placar', 'recados', 'boletins', 'usuarios'] as $t) {
        $pdo->exec("DROP TABLE IF EXISTS `$t`");
    }
    $pdo->exec('SET FOREIGN_KEY_CHECKS=1');

    $pdo->exec("
        CREATE TABLE usuarios (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            nome       VARCHAR(120) NOT NULL,
            usuario    VARCHAR(60)  NOT NULL UNIQUE,
            senha      VARCHAR(255) NOT NULL,
            senha_hash VARCHAR(255) NOT NULL,
            email      VARCHAR(160) NOT NULL,
            cpf        VARCHAR(14)  NOT NULL,
            role       VARCHAR(20)  NOT NULL DEFAULT 'aluno',
            matricula  VARCHAR(20)  NOT NULL,
            avatar     VARCHAR(255) NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $log[] = 'Tabela usuarios criada.';

    $pdo->exec("
        CREATE TABLE boletins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            usuario_id INT NOT NULL,
            disciplina VARCHAR(120) NOT NULL,
            nota DECIMAL(4,2) NOT NULL,
            situacao VARCHAR(20) NOT NULL,
            observacao VARCHAR(255) NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $log[] = 'Tabela boletins criada.';

    $pdo->exec("
        CREATE TABLE recados (
            id INT AUTO_INCREMENT PRIMARY KEY,
            autor VARCHAR(80) NOT NULL,
            texto VARCHAR(500) NOT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $log[] = 'Tabela recados criada.';

    $pdo->exec("
        CREATE TABLE placar (
            id INT AUTO_INCREMENT PRIMARY KEY,
            equipe VARCHAR(80) NOT NULL,
            codigo VARCHAR(40) NOT NULL,
            pontos INT NOT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_equipe_codigo (equipe, codigo)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $log[] = 'Tabela placar criada.';

    // Seed de usuários. senha = texto puro (modo vulnerável); senha_hash = bcrypt.
    $flagUnion = flags_catalogo()['SQLI_UNION']['flag'];
    $usuarios = [
        // nome, usuario, senha, email, cpf, role, matricula
        ['Ana Aluna',       'aluno1',   '123',     'ana.aluna@ifac.edu', '111.111.111-11', 'aluno',    '2025A001'],
        ['Bruno Aluno',     'aluno2',   'bruno',   'bruno@ifac.edu',     '222.222.222-22', 'aluno',    '2025A002'],
        ['Clara Aluna',     'aluno3',   'senha',   'clara@ifac.edu',     '333.333.333-33', 'aluno',    '2025A003'],
        ['Prof. Pereira',   'prof1',    '123',     'pereira@ifac.edu',   '444.444.444-44', 'professor','PROF010'],
        ['Admin do Portal', 'admin',    'admin',   'admin@ifac.edu',     '000.000.000-00', 'admin',    'ADM001'],
        // Linha de sistema: o UNION SELECT usuario, senha a traz à tona (missão SQLI_UNION).
        ['(conta de sistema)', '_sistema_', $flagUnion, 'sistema@ifac.local', '—', 'sistema', 'SYS000'],
    ];
    $ins = $pdo->prepare('INSERT INTO usuarios
        (nome,usuario,senha,senha_hash,email,cpf,role,matricula,avatar)
        VALUES (?,?,?,?,?,?,?,?,?)');
    foreach ($usuarios as $u) {
        $ins->execute([$u[0],$u[1],$u[2],password_hash($u[2],PASSWORD_BCRYPT),
                       $u[3],$u[4],$u[5],$u[6],'default.png']);
    }
    $log[] = count($usuarios) . ' usuários inseridos.';

    $boletins = [
        [1,'Algoritmos',9.2,'Aprovado','Ótimo desempenho'],
        [1,'Banco de Dados',7.5,'Aprovado',''],
        [2,'Redes de Computadores',5.0,'Recuperação','Faltou às provas'],
        [2,'Algoritmos',8.1,'Aprovado',''],
        [3,'Segurança da Informação',10.0,'Aprovado','Achou todas as flags :)'],
    ];
    $insb = $pdo->prepare('INSERT INTO boletins
        (usuario_id,disciplina,nota,situacao,observacao) VALUES (?,?,?,?,?)');
    foreach ($boletins as $bo) { $insb->execute($bo); }
    $log[] = count($boletins) . ' boletins inseridos.';

    $pdo->prepare('INSERT INTO recados (autor,texto) VALUES (?,?)')
        ->execute(['Coordenação', 'Bem-vindos ao mural da turma! Sejam gentis. :)']);
    $log[] = 'Recado inicial inserido.';

    // Arquivos-alvo das missões de Injection.
    @mkdir(STORAGE_DIR, 0777, true);
    @file_put_contents(STORAGE_DIR . '/flag_xxe.txt',
        flags_catalogo()['XXE']['flag'] . "\n");
    @file_put_contents(STORAGE_DIR . '/flag_cmd.txt',
        flags_catalogo()['CMDI']['flag'] . "\n");
    @file_put_contents(STORAGE_DIR . '/leia-me.txt',
        "Pasta de trabalho da coordenação (arquivos internos).\n");
    $log[] = 'Arquivos-alvo em storage/ (flag_xxe.txt, flag_cmd.txt) gravados.';

    @mkdir(UPLOAD_DIR, 0777, true);
    @file_put_contents(UPLOAD_DIR . '/default.png', "PNG falso (placeholder)\n");

    // Reforça o .htaccess de uploads (não essencial para as missões desta aula).
    @file_put_contents(UPLOAD_DIR . '/.htaccess', "Options -Indexes\n");

} catch (Throwable $e) {
    $erro = $e->getMessage();
}

$b = base_url();
?>
<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Instalador — Aula 2</title>
<style>
 body{font:15px/1.6 system-ui,Segoe UI,Arial;background:#0f1420;color:#e8edf6;max-width:760px;margin:40px auto;padding:0 16px}
 .card{background:#1a2233;border:1px solid #2b3850;border-radius:12px;padding:20px;margin:16px 0}
 code,pre{background:#0b1220;border:1px solid #2b3850;border-radius:6px;padding:2px 6px}
 .ok{color:#2ecc71}.err{color:#ff5c7a}
 a.btn{display:inline-block;background:#4f8cff;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none;margin-top:8px}
 table{width:100%;border-collapse:collapse}td{padding:4px 8px;border-bottom:1px solid #2b3850}
</style></head><body>
<h1>🎓 Instalador — Portal Acadêmico IFAC · Aula 2</h1>
<p class="err"><strong>A05 Injection + A02 Security Misconfiguration.</strong>
   App vulnerável de propósito — só em laboratório isolado.</p>
<?php if ($erro): ?>
  <div class="card"><h2 class="err">Falha na instalação</h2>
    <pre><?= htmlspecialchars($erro) ?></pre>
    <p>Confira no XAMPP se o <strong>MySQL</strong> está no ar e as credenciais em
       <code>config.php</code> (padrão: <code>root</code>, senha vazia).</p></div>
<?php else: ?>
  <div class="card"><h2 class="ok">✔ Instalado com sucesso!</h2>
    <ul><?php foreach ($log as $l): ?><li class="ok">✔ <?= htmlspecialchars($l) ?></li><?php endforeach; ?></ul>
    <a class="btn" href="<?= htmlspecialchars($b) ?>/index.php">Ir para o portal →</a></div>
  <div class="card"><h3>Contas de demonstração</h3>
    <table>
      <tr><td><code>aluno1</code></td><td><code>123</code></td><td>aluno</td></tr>
      <tr><td><code>prof1</code></td><td><code>123</code></td><td>professor</td></tr>
      <tr><td><code>admin</code></td><td><code>admin</code></td><td>admin</td></tr>
    </table>
    <p class="err">Depois da aula, derrube o site e/ou apague o banco
       <code><?= DB_NAME ?></code>.</p></div>
<?php endif; ?>
</body></html>
