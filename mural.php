<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';
$b = base_url();
$u = current_user();

// Novo recado.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $autor = trim($_POST['autor'] ?? ($u['nome'] ?? 'Anônimo'));
    $texto = (string) ($_POST['texto'] ?? '');
    if ($texto !== '') {
        // Guardamos o texto como veio. A falha de XSS armazenado (CWE-79) está
        // na HORA DE EXIBIR, não aqui — em modo seguro a saída é escapada.
        $st = db()->prepare('INSERT INTO recados (autor, texto) VALUES (?, ?)');
        $st->execute([mb_substr($autor, 0, 80), mb_substr($texto, 0, 500)]);
    }
    header('Location: ' . $b . '/mural.php');
    exit;
}

$recados = db()->query('SELECT * FROM recados ORDER BY id DESC LIMIT 50')->fetchAll();

// Algum recado guardado contém payload de script? (para revelar a flag)
$temPayload = false;
foreach ($recados as $r) {
    if (preg_match('/<\s*script|onerror\s*=|onload\s*=|<\s*img|<\s*svg/i', $r['texto'])) {
        $temPayload = true; break;
    }
}

page_header('Mural de recados');
?>
<div class="card">
  <h2>Mural de recados</h2>
  <form method="post">
    <label>Autor</label>
    <input name="autor" value="<?= e($u['nome'] ?? '') ?>">
    <label>Recado</label>
    <textarea name="texto" rows="3" placeholder="Escreva algo para a turma…"></textarea>
    <div style="margin-top:12px"><button class="btn">Publicar</button></div>
  </form>
</div>

<?php if (!SECURE && $temPayload): ?>
<div class="card" style="border-color:var(--secure)">
  <h3>🏴 XSS armazenado!</h3>
  <p class="muted">Um recado com script ficou guardado e é renderizado sem escape
     para todo mundo que abre o mural. Flag:</p>
  <p><span class="flag"><?= e(flags_catalogo()['XSS_STORED']['flag']) ?></span></p>
</div>
<?php endif; ?>

<div class="card">
  <h3>Recados</h3>
  <?php if (!$recados): ?>
    <p class="muted">Nenhum recado ainda.</p>
  <?php else: foreach ($recados as $r): ?>
    <div style="border-bottom:1px solid var(--line);padding:8px 0">
      <div class="muted" style="font-size:12px"><?= e($r['autor']) ?> ·
        <?= e($r['criado_em']) ?></div>
      <!-- Vulnerável: texto impresso CRU. Seguro: escapado com e(). -->
      <div><?= SECURE ? e($r['texto']) : $r['texto'] ?></div>
    </div>
  <?php endforeach; endif; ?>
</div>
<?php page_footer();
