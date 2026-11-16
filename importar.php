<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';
$b = base_url();

/**
 * MISSÃO XXE — XML External Entity (A05 / CWE-611, CWE-827).
 * O importador processa XML enviado pelo usuário. Em modo vulnerável ele
 * resolve ENTIDADES EXTERNAS, então um <!DOCTYPE ... <!ENTITY xxe SYSTEM
 * "file:///...">> faz o parser LER UM ARQUIVO do servidor e devolvê-lo.
 */
$xmlPadrao = "<notas>\n  <aluno>Ana Aluna</aluno>\n  <disciplina>Redes</disciplina>\n  <nota>9.0</nota>\n</notas>";
$xml = $_POST['xml'] ?? $xmlPadrao;

$itens = [];
$erro  = null;
$flagXxe = null;
$flagEsperada = flags_catalogo()['XXE']['flag'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $prev = libxml_use_internal_errors(true);
    $dom  = new DOMDocument();
    $ok   = false;

    if (SECURE) {
        // ---- Corrigido: bloqueia DTD/entidades externas e não usa rede.
        if (stripos($xml, '<!DOCTYPE') !== false || stripos($xml, '<!ENTITY') !== false) {
            $erro = 'DTD/entidades não são permitidos neste importador.';
        } else {
            libxml_set_external_entity_loader(fn() => null);
            $ok = $dom->loadXML($xml, LIBXML_NONET | LIBXML_NOENT);
        }
    } else {
        // ---- VULNERÁVEL: resolve entidades externas (carrega file:// etc.).
        libxml_set_external_entity_loader(function ($public, $system, $context) {
            // Carrega o recurso apontado pela entidade (inclui file://) — a falha.
            return ($system && is_string($system)) ? @fopen($system, 'rb') : null;
        });
        $ok = $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
    }

    if ($ok && $dom->documentElement) {
        // Mostra o texto de cada elemento filho (onde a entidade seria expandida).
        foreach ($dom->documentElement->childNodes as $n) {
            if ($n->nodeType === XML_ELEMENT_NODE) {
                $itens[] = [$n->nodeName, trim($n->textContent)];
            }
        }
        // Se o conteúdo lido trouxe a flag do arquivo-alvo, missão cumprida.
        if (!SECURE && str_contains($dom->textContent, $flagEsperada)) {
            $flagXxe = $flagEsperada;
        }
    } elseif ($erro === null) {
        $e = libxml_get_last_error();
        $erro = $e ? trim($e->message) : 'XML inválido.';
    }
    libxml_use_internal_errors($prev);
}

$alvo = STORAGE_DIR . DIRECTORY_SEPARATOR . 'flag_xxe.txt';
page_header('Importar notas (XML)');
?>
<div class="card">
  <h2>Importar notas (XML)</h2>
  <form method="post">
    <label>Cole o XML</label>
    <textarea name="xml" rows="8" class="mono"><?= e($xml) ?></textarea>
    <div style="margin-top:12px"><button class="btn">Importar</button></div>
  </form>
  <?php if (!SECURE): ?>
  <p class="muted" style="font-size:12px;margin-top:10px">
    Dica: o parser expande entidades externas. Existe um arquivo-alvo em
    <code class="mono"><?= e($alvo) ?></code>. Monte um <code>&lt;!DOCTYPE&gt;</code>
    com <code>&lt;!ENTITY xxe SYSTEM "file://<?= e(str_replace('\\','/',$alvo)) ?>"&gt;</code>
    e referencie <code>&amp;xxe;</code> dentro de um elemento.</p>
  <?php endif; ?>
</div>

<?php if ($flagXxe): ?>
<div class="card" style="border-color:var(--secure)">
  <h3>🏴 XXE — você leu um arquivo do servidor!</h3>
  <p><span class="flag"><?= e($flagXxe) ?></span></p>
</div>
<?php endif; ?>

<?php if ($erro): ?>
  <div class="card"><div class="alert err mono" style="font-size:12px"><?= e($erro) ?></div></div>
<?php elseif ($itens): ?>
<div class="card">
  <h3>Conteúdo importado</h3>
  <table>
    <tr><th>Campo</th><th>Valor</th></tr>
    <?php foreach ($itens as $it): ?>
      <tr><td><?= e($it[0]) ?></td><td class="mono"><?= e($it[1]) ?></td></tr>
    <?php endforeach; ?>
  </table>
</div>
<?php endif; ?>
<?php page_footer();
