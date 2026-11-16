<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';
$u = require_login();
$b = base_url();

// Boletins do próprio usuário (consulta parametrizada — aqui não é a lição).
$st = db()->prepare('SELECT * FROM boletins WHERE usuario_id = ?');
$st->execute([$u['id']]);
$boletins = $st->fetchAll();

// Flag de SQLi no login (se o acesso veio por injeção).
$flagSqli = $_SESSION['flag_sqli_login'] ?? null;
unset($_SESSION['flag_sqli_login']);

page_header('Painel');
?>
<?php if ($flagSqli): ?>
<div class="card" style="border-color:var(--secure)">
  <h3>🏴 Login por SQL Injection!</h3>
  <p class="muted">Você entrou sem uma senha válida — a consulta de login foi
     burlada. Esta é a flag da missão <strong>SQL Injection: bypass de login</strong>:</p>
  <p><span class="flag"><?= e($flagSqli) ?></span></p>
</div>
<?php endif; ?>
<div class="card">
  <h2>Olá, <?= e($u['nome']) ?> <span class="muted">(<?= e($u['role']) ?>)</span></h2>
  <p class="muted">Matrícula <?= e($u['matricula']) ?> · <?= e($u['email']) ?></p>
  <p>
    <a class="btn ghost" href="<?= e($b) ?>/busca.php">Buscar colegas</a>
    <a class="btn ghost" href="<?= e($b) ?>/mural.php">Mural de recados</a>
    <a class="btn ghost" href="<?= e($b) ?>/diagnostico.php">Diagnóstico de rede</a>
    <a class="btn ghost" href="<?= e($b) ?>/importar.php">Importar notas (XML)</a>
  </p>
</div>

<div class="card">
  <h3>Resumo das disciplinas</h3>
  <?php if ($boletins): ?>
  <table>
    <tr><th>Disciplina</th><th>Nota</th><th>Situação</th></tr>
    <?php foreach ($boletins as $bo): ?>
      <tr><td><?= e($bo['disciplina']) ?></td><td><?= e($bo['nota']) ?></td><td><?= e($bo['situacao']) ?></td></tr>
    <?php endforeach; ?>
  </table>
  <?php else: ?><p class="muted">Sem lançamentos.</p><?php endif; ?>
</div>
<?php page_footer();
