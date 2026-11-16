<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';
$b = base_url();

$resultado = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $equipe = $_POST['equipe'] ?? '';
    $flag   = $_POST['flag'] ?? '';
    $resultado = registrar_flag($equipe, $flag);
    // Lembra o nome da equipe para o próximo envio.
    if ($equipe !== '') { setcookie('equipe', $equipe, time() + 86400, '/'); }
}
$equipeAtual = $_POST['equipe'] ?? ($_COOKIE['equipe'] ?? '');

$catalogo   = flags_catalogo();
$totalFlags = count($catalogo);

// Busca todas as capturas e agrega por equipe (total, nº de flags e quais missões).
$capturas = db()->query(
    'SELECT equipe, codigo, pontos FROM placar ORDER BY equipe'
)->fetchAll();

$times = [];
foreach ($capturas as $c) {
    $eq = $c['equipe'];
    if (!isset($times[$eq])) {
        $times[$eq] = ['total' => 0, 'flags' => 0, 'missoes' => []];
    }
    $times[$eq]['total']    += (int) $c['pontos'];
    $times[$eq]['flags']++;
    $times[$eq]['missoes'][] = $catalogo[$c['codigo']]['titulo'] ?? $c['codigo'];
}
// Ordena por pontos (desc) e, em empate, por nº de flags (desc).
uasort($times, fn($a, $b) => ($b['total'] <=> $a['total']) ?: ($b['flags'] <=> $a['flags']));

page_header('Placar');
?>
<style>
  .chips{display:flex;flex-wrap:wrap;gap:4px;margin-top:4px}
  .chip{font-size:11px;padding:2px 8px;border-radius:999px;
        background:rgba(46,204,113,.14);border:1px solid var(--secure);color:#7bffb0}
  .chip-none{font-size:12px;color:var(--mut)}
</style>
<div class="card">
  <h2>Enviar flag</h2>
  <?php if ($resultado): ?>
    <div class="alert <?= $resultado['ok'] ? 'ok' : 'err' ?>">
      <?= e($resultado['msg']) ?>
      <?= $resultado['ok'] ? '(+' . (int)$resultado['pontos'] . ' pts)' : '' ?>
    </div>
  <?php endif; ?>
  <form method="post">
    <label>Equipe / seu nome</label>
    <input name="equipe" value="<?= e($equipeAtual) ?>" required>
    <label>Flag</label>
    <input name="flag" placeholder="FLAG{...}" class="mono" required>
    <div style="margin-top:14px"><button class="btn">Pontuar</button></div>
  </form>
  <p class="muted" style="margin-top:10px">São <?= $totalFlags ?> flags no total.</p>
</div>

<div class="card">
  <h2>Ranking</h2>
  <?php if ($times): ?>
  <table>
    <tr><th>#</th><th>Equipe</th><th>Flags</th><th>Pontos</th><th>Missões concluídas</th></tr>
    <?php $pos = 1; foreach ($times as $equipe => $t): ?>
      <tr>
        <td><?= $pos++ ?></td>
        <td><?= e($equipe) ?></td>
        <td><?= (int) $t['flags'] ?>/<?= $totalFlags ?></td>
        <td><strong><?= (int) $t['total'] ?></strong></td>
        <td>
          <?php if ($t['missoes']): ?>
            <div class="chips">
              <?php foreach ($t['missoes'] as $m): ?>
                <span class="chip">✔ <?= e($m) ?></span>
              <?php endforeach; ?>
            </div>
          <?php else: ?>
            <span class="chip-none">—</span>
          <?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
  </table>
  <?php else: ?><p class="muted">Ninguém pontuou ainda. Seja o primeiro!</p><?php endif; ?>
</div>
<?php page_footer();
