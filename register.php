<?php
require_once __DIR__ . '/lib/render.php';

$msg = null; $erro = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nome    = trim($_POST['nome'] ?? '');
    $usuario = trim($_POST['usuario'] ?? '');
    $senha   = (string) ($_POST['senha'] ?? '');
    $email   = trim($_POST['email'] ?? '');
    if ($nome === '' || $usuario === '' || $senha === '') {
        $erro = 'Preencha nome, usuário e senha.';
    } else {
        try {
            $st = db()->prepare('INSERT INTO usuarios
                (nome,usuario,senha,senha_hash,email,cpf,role,matricula,avatar)
                VALUES (?,?,?,?,?,?,?,?,?)');
            $st->execute([$nome, $usuario, $senha,
                password_hash($senha, PASSWORD_BCRYPT),
                $email, '000.000.000-00', 'aluno', 'NOVO-' . random_int(1000, 9999),
                'default.png']);
            $msg = 'Conta criada! Já pode entrar.';
        } catch (PDOException $ex) {
            $erro = 'Não foi possível cadastrar (usuário já existe?).';
        }
    }
}
page_header('Cadastro');
?>
<div class="card" style="max-width:440px;margin:30px auto">
  <h2>Criar conta</h2>
  <?php if ($msg): ?><div class="alert ok"><?= e($msg) ?></div><?php endif; ?>
  <?php if ($erro): ?><div class="alert err"><?= e($erro) ?></div><?php endif; ?>
  <form method="post">
    <label>Nome</label><input name="nome">
    <label>Usuário</label><input name="usuario" autocomplete="off">
    <label>E-mail</label><input name="email">
    <label>Senha</label><input type="password" name="senha" autocomplete="off">
    <div style="margin-top:14px"><button class="btn">Cadastrar</button></div>
  </form>
  <p class="muted" style="margin-top:14px"><a href="<?= e(base_url()) ?>/login.php">Voltar ao login</a></p>
</div>
<?php page_footer();
