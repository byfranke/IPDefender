<?php
$ip = $_SERVER['REMOTE_ADDR'];
$log = '/var/log/ipdefender/web_honeypot.log';
$timestamp = date('Y-m-d H:i:s');

// Cria o diretório de log se necessário
if (!is_dir(dirname($log))) {
    mkdir(dirname($log), 0755, true);
}

// Log local
file_put_contents($log, "[$timestamp] WebHoneypot Detected: $ip\n", FILE_APPEND);

// Executa o bloqueio via Cloudflare
$cloudflareScript = '/etc/ipdefender/modules/cloudflare-ban.py';
if (file_exists($cloudflareScript)) {
    exec("python3 $cloudflareScript add $ip > /dev/null 2>&1 &");
}

// Executa o bloqueio via IPDefender
exec("IPDefender --ban $ip 'WebHoneypot Detection' > /dev/null 2>&1 &");

// Redireciona para página web
header("Location: https://byfranke.com/");
exit;
?>