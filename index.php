<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';

$b = base_url();
page_header('Início');
?>
<div class="card">
  <h1>Portal Acadêmico IFAC — Aula 2</h1>
  <p class="muted">Laboratório prático — <strong>OWASP Top 10 2025</strong>:
     <strong>A05 Injection</strong> + <strong>A02 Security Misconfiguration</strong>.
     Encontre, explore e corrija as falhas. Cada missão revela uma
     <span class="flag">FLAG{...}</span> que você envia no
     <a href="<?= e($b) ?>/placar.php">placar</a>.</p>
  <p>
    <?php if (SECURE): ?>
      Site em <span class="pill pill-secure">MODO SEGURO</span>: correções ativas,
      os ataques devem falhar. Use o botão no topo para voltar ao modo vulnerável.
    <?php else: ?>
      Site em <span class="pill pill-vuln">MODO VULNERÁVEL</span>: mãos à obra.
    <?php endif; ?>
  </p>
</div>

<div class="card">
  <h2>Missões</h2>
  <table>
    <tr><th>#</th><th>Missão</th><th>Categoria</th><th>Onde começar</th><th>Pontos</th><th class="cwe">CWE</th></tr>
    <?php
    $pistas = [
      'SQLI_LOGIN'  => ['login.php', 'tente <code>admin'."'".' --</code> no usuário.'],
      'SQLI_UNION'  => ['busca.php', 'a busca aceita <code>UNION SELECT</code> de 2 colunas.'],
      'XSS_REFLECT' => ['busca.php', 'o termo volta para a página sem escape.'],
      'XSS_STORED'  => ['mural.php', 'um recado com &lt;script&gt; fica salvo para todos.'],
      'CMDI'        => ['diagnostico.php', 'o host vai pro shell: <code>; cat flag_cmd.txt</code>.'],
      'XXE'         => ['importar.php', 'o XML expande entidades externas (file://).'],
      'DEFAULTCRED' => ['admin-legado/', 'console legado com senha de fábrica.'],
      'VERBOSE'     => ['exportar.php', 'provoque um erro (<code>?col=xyz</code>) e leia o que vaza.'],
      'DEBUGPARAM'  => ['status.php', 'existe um parâmetro de depuração escondido.'],
      'CORS'        => ['api/relatorio.php', 'a API responde com CORS liberado para todos.'],
      'HEADERS'     => ['headers.php', 'faltam cabeçalhos de proteção (clickjacking).'],
    ];
    $i = 1;
    foreach (flags_catalogo() as $cod => $info):
      [$pista, $dica] = $pistas[$cod] ?? ['', ''];
      $linkable = $pista !== '';
    ?>
    <tr>
      <td><?= $i++ ?></td>
      <td><?= e($info['titulo']) ?></td>
      <td class="cwe"><?= e($info['cat']) ?></td>
      <td class="mono">
        <?php if ($linkable): ?>
          <a href="<?= e($b . '/' . $pista) ?>"><?= e($pista) ?></a>
        <?php endif; ?>
        <?php if ($dica): ?>
          <div class="muted" style="font-size:12px;margin-top:3px">💡 <?= $dica ?></div>
        <?php endif; ?>
      </td>
      <td><?= (int) $info['pontos'] ?></td>
      <td class="cwe"><?= e($info['cwe']) ?></td>
    </tr>
    <?php endforeach; ?>
  </table>
</div>
<?php page_footer();
