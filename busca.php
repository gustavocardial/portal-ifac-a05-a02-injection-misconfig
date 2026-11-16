<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';
$b = base_url();

$q = (string) ($_GET['q'] ?? '');
$resultados = [];
$erroSql = null;

if ($q !== '') {
    if (SECURE) {
        // ---- Corrigido: consulta parametrizada e só papéis "públicos".
        $st = db()->prepare(
            "SELECT nome, email FROM usuarios
             WHERE role IN ('aluno','professor') AND nome LIKE ?");
        $st->execute(['%' . $q . '%']);
        $resultados = $st->fetchAll();
    } else {
        // ---- VULNERÁVEL: termo concatenado na query -> SQL Injection (CWE-89).
        //      UNION revela colunas sensíveis de outras linhas/tabelas.
        //      Ex.:  ' UNION SELECT usuario, senha FROM usuarios --
        $sql = "SELECT nome, email FROM usuarios WHERE nome LIKE '%$q%'";
        try {
            $resultados = db()->query($sql)->fetchAll();
        } catch (PDOException $ex) {
            $erroSql = $ex->getMessage() . "\nquery: $sql";
        }
    }
}

// Missão XSS refletido: em modo vulnerável o termo volta CRU para o HTML.
$payloadXss = (bool) preg_match('/<\s*script|onerror\s*=|onload\s*=|<\s*img|<\s*svg/i', $q);

page_header('Buscar colegas');
?>
<div class="card">
  <h2>Buscar colegas</h2>
  <form method="get">
    <label>Nome</label>
    <input name="q" value="<?= SECURE ? e($q) : $q /* vulnerável: sem escape */ ?>">
    <div style="margin-top:12px"><button class="btn">Buscar</button></div>
  </form>
</div>

<?php if ($q !== ''): ?>
<div class="card">
  <!-- Reflexão do termo: em modo vulnerável, sem htmlspecialchars (CWE-79). -->
  <p>Resultados para: <strong><?= SECURE ? e($q) : $q ?></strong></p>

  <?php if (!SECURE && $payloadXss): ?>
    <div class="alert ok">
      🏴 Seu HTML/JS foi refletido sem escape — <strong>XSS refletido</strong>.
      Flag: <span class="flag"><?= e(flags_catalogo()['XSS_REFLECT']['flag']) ?></span>
    </div>
  <?php endif; ?>

  <?php if ($erroSql): ?>
    <pre class="dump"><?= e($erroSql) ?></pre>
  <?php endif; ?>

  <?php if ($resultados): ?>
  <table>
    <tr><th>Nome / Coluna 1</th><th>E-mail / Coluna 2</th></tr>
    <?php foreach ($resultados as $r): ?>
      <tr><td><?= e($r['nome']) ?></td><td class="mono"><?= e($r['email']) ?></td></tr>
    <?php endforeach; ?>
  </table>
  <p class="muted" style="font-size:12px;margin-top:8px">
    Dica: a consulta devolve 2 colunas. Um <code>UNION SELECT</code> de 2 colunas
    pode trazer dados de qualquer linha — inclusive o que não deveria aparecer aqui.</p>
  <?php else: ?>
    <p class="muted">Nenhum resultado.</p>
  <?php endif; ?>
</div>
<?php endif; ?>
<?php page_footer();
