<?php
require_once __DIR__ . '/lib/render.php';
require_once __DIR__ . '/lib/flags.php';
$b = base_url();

/**
 * MISSÃO CMDI — Command Injection (A05 / CWE-78, CWE-77).
 *
 * Um app real passaria o host direto para o shell, algo como:
 *     shell_exec('ping -c 1 ' . $host);
 * e um host como  "127.0.0.1; cat /etc/passwd"  executaria o segundo comando.
 *
 * Para NÃO abrir execução arbitrária de verdade na máquina da aula, aqui o
 * "shell" é SIMULADO: ele interpreta os separadores (;  |  &&) exatamente como
 * um shell faria e roda um conjunto pequeno de comandos sobre a pasta storage/.
 * A lição — a entrada não validada vira comando — fica idêntica. Fazer
 * `cat flag_cmd.txt` depois de um `;` revela a flag.
 */
function shell_simulado_segmento(string $seg): string {
    $seg = trim($seg);
    if ($seg === '') return '';
    $tok = preg_split('/\s+/', $seg);
    $cmd = strtolower($tok[0]);
    $arg = $tok[1] ?? '';
    switch ($cmd) {
        case 'ping':
            $alvo = $arg !== '' ? $arg : 'host';
            return "PING $alvo: 56 data bytes\n"
                 . "64 bytes de $alvo: icmp_seq=0 ttl=64 tempo=0.045 ms\n"
                 . "--- estatísticas de $alvo ---\n"
                 . "1 pacotes transmitidos, 1 recebidos, 0% de perda";
        case 'cat': case 'type':
            $f = STORAGE_DIR . '/' . basename(str_replace('\\', '/', $arg));
            if (is_file($f)) return rtrim((string) file_get_contents($f));
            return ($arg === '' ? 'cat: falta o arquivo' : "cat: $arg: arquivo não encontrado");
        case 'ls': case 'dir':
            $itens = array_values(array_filter(scandir(STORAGE_DIR),
                fn($x) => $x !== '.' && $x !== '..'));
            return implode("\n", $itens);
        case 'whoami': return 'www-data';
        case 'id':     return 'uid=33(www-data) gid=33(www-data) groups=33(www-data)';
        case 'echo':   return implode(' ', array_slice($tok, 1));
        default:       return "$cmd: comando não encontrado";
    }
}

$host   = (string) ($_GET['host'] ?? '');
$saida  = null;
$flagCmd = null;

if ($host !== '') {
    if (SECURE) {
        // ---- Corrigido: valida o host (allowlist) e NÃO monta linha de shell.
        if (preg_match('/^[A-Za-z0-9.\-]{1,64}$/', $host)) {
            $saida = shell_simulado_segmento('ping ' . $host);
        } else {
            $saida = 'Host inválido. Use apenas letras, números, ponto e hífen.';
        }
    } else {
        // ---- VULNERÁVEL: o host entra cru na "linha de comando".
        $linha = 'ping ' . $host;   // ex.: ping 127.0.0.1; cat flag_cmd.txt
        // O shell divide por ;  |  &&  &  — exatamente a brecha explorada.
        $segs  = preg_split('/\s*(?:;|\|\||&&|\||&)\s*/', $linha);
        $partes = array_map('shell_simulado_segmento', $segs);
        $saida  = implode("\n", array_filter($partes, fn($x) => $x !== ''));
        $flagEsperada = flags_catalogo()['CMDI']['flag'];
        if (str_contains($saida, $flagEsperada)) {
            $flagCmd = $flagEsperada;
        }
    }
}

page_header('Diagnóstico de rede');
?>
<div class="card">
  <h2>Diagnóstico de rede — ping</h2>
  <p class="muted">Ferramenta interna da coordenação para testar se um host responde.</p>
  <form method="get">
    <label>Host ou IP</label>
    <input name="host" value="<?= e($host) ?>" placeholder="127.0.0.1" class="mono">
    <div style="margin-top:12px"><button class="btn">Executar ping</button></div>
  </form>
  <?php if (!SECURE): ?>
    <p class="muted" style="font-size:12px;margin-top:10px">
      Por baixo roda <code class="mono">ping &lt;host&gt;</code>. E se o host tiver
      mais que um host? 😏 (dica: há arquivos em <code>storage/</code> — tente
      <code class="mono">; cat flag_cmd.txt</code>)</p>
  <?php endif; ?>
</div>

<?php if ($flagCmd): ?>
<div class="card" style="border-color:var(--secure)">
  <h3>🏴 Command Injection!</h3>
  <p class="muted">Seu <code>;</code> encerrou o ping e o segundo comando rodou.
     Flag:</p>
  <p><span class="flag"><?= e($flagCmd) ?></span></p>
</div>
<?php endif; ?>

<?php if ($saida !== null): ?>
<div class="card">
  <h3>Saída</h3>
  <pre class="dump" style="color:#bfe9ff"><?= e($saida) ?></pre>
</div>
<?php endif; ?>
<?php page_footer();
