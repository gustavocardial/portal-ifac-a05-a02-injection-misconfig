<?php
require_once __DIR__ . '/lib/render.php';
$u = require_login();
$b = base_url();
$msg = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_check()) {
        $msg = ['err', 'Falha na verificação CSRF.'];
    } else {
        $email = trim($_POST['email'] ?? '');
        $st = db()->prepare('UPDATE usuarios SET email = ? WHERE id = ?');
        $st->execute([$email, $u['id']]);
        $u['email'] = $email;
        $msg = ['ok', 'Perfil atualizado.'];
    }
}

page_header('Meu perfil');
?>
<div class="card" style="max-width:480px">
  <h2>Meu perfil</h2>
  <?php if ($msg): ?><div class="alert <?= $msg[0] ?>"><?= e($msg[1]) ?></div><?php endif; ?>
  <form method="post">
    <?= csrf_field() ?>
    <label>Nome</label><input value="<?= e($u['nome']) ?>" disabled>
    <label>Papel</label><input value="<?= e($u['role']) ?>" disabled>
    <label>E-mail</label><input name="email" value="<?= e($u['email']) ?>">
    <div style="margin-top:14px"><button class="btn">Salvar</button></div>
  </form>
</div>
<?php page_footer();
