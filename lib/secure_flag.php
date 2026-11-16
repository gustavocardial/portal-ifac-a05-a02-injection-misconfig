<?php
/**
 * Define a constante SECURE combinando o padrão global (config.php) com um
 * override que o professor liga/desliga pelo botão no topo do site.
 *
 * O override é guardado num cookie próprio (não na sessão) porque precisamos
 * conhecer o valor de SECURE ANTES de iniciar a sessão — é justamente SECURE
 * que decide os parâmetros (SameSite) do cookie de sessão.
 *
 * Precedência:
 *   1) ?toggle_secure=on|off  -> grava o cookie de override
 *   2) cookie de override, se existir
 *   3) SECURE_DEFAULT (config.php)
 */

if (!defined('SECURE')) {
    if (isset($_GET['toggle_secure'])) {
        $on = ($_GET['toggle_secure'] === 'on');
        setcookie('secure_override', $on ? '1' : '0', [
            'expires'  => 0,
            'path'     => '/',
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        $_COOKIE['secure_override'] = $on ? '1' : '0'; // vale já nesta requisição
    }

    if (array_key_exists('secure_override', $_COOKIE)) {
        define('SECURE', $_COOKIE['secure_override'] === '1');
    } else {
        define('SECURE', SECURE_DEFAULT);
    }
}
