<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';

$erro = null;
$b = base_url();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $usuario = (string) ($_POST['usuario'] ?? '');
    $senha   = (string) ($_POST['senha'] ?? '');

    if (SECURE) {
        // ---- Versão corrigida: consulta parametrizada + verificação de hash.
        $st = db()->prepare('SELECT * FROM usuarios WHERE usuario = ?');
        $st->execute([$usuario]);
        $u = $st->fetch();
        if ($u && password_verify($senha, (string) ($u['senha_hash'] ?? ''))) {
            login_user($u);
            header('Location: ' . $b . '/dashboard.php');
            exit;
        }
        $erro = 'Usuário ou senha inválidos.';
    } else {
        // ---- Versão VULNERÁVEL: a senha e o usuário entram CRUS na query
        //      (concatenação de string) -> SQL Injection (CWE-89).
        //      Payload clássico no usuário:   admin' --
        //      ou:                            ' OR '1'='1' LIMIT 1 --
        $sql = "SELECT * FROM usuarios
                WHERE usuario = '$usuario' AND senha = '$senha'";
        try {
            $u = db()->query($sql)->fetch();
        } catch (PDOException $ex) {
            // Em modo vulnerável o erro de SQL vaza na tela (ajuda o atacante).
            $erro = 'Erro de SQL: ' . $ex->getMessage() . '  —  (query: ' . $sql . ')';
            $u = false;
        }
        if ($u) {
            login_user($u);
            // A senha informada realmente confere com a do banco? Se NÃO, o
            // login só aconteceu por causa da injeção -> revela a flag.
            if (!hash_equals((string) $u['senha'], $senha)) {
                $_SESSION['flag_sqli_login'] = flags_catalogo()['SQLI_LOGIN']['flag'];
            }
            header('Location: ' . $b . '/dashboard.php');
            exit;
        }
        if ($erro === null) {
            $erro = 'Usuário ou senha inválidos.';
        }
    }
}

page_header('Entrar');
?>
<div class="card" style="max-width:440px;margin:30px auto">
  <h2>Entrar no portal</h2>
  <?php if ($erro): ?><div class="alert err mono" style="font-size:12px"><?= e($erro) ?></div><?php endif; ?>
  <form method="post">
    <label>Usuário</label>
    <input name="usuario" autofocus autocomplete="off">
    <label>Senha</label>
    <input type="password" name="senha" autocomplete="off">
    <div style="margin-top:14px"><button class="btn">Entrar</button></div>
  </form>
  <p class="muted" style="margin-top:14px">Contas de teste em <code>README.md</code>.
     Não tem conta? <a href="<?= e($b) ?>/register.php">Cadastre-se</a>.</p>
</div>
<?php page_footer();
