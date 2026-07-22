<?php
// Usage: php -d extension=openssl check-host.php

$host = $_GET['host'] ?? $argv[1] ?? 'example.com';

$context = stream_context_create([
    'ssl' => [
        'peer_name' => $host,
        'capture_peer_cert_chain' => true,
        'verify_peer' => false,
        'verify_peer_name' => false,
    ]
]);

$fp = stream_socket_client("ssl://$host:443", $error_code, $error_message, null, STREAM_CLIENT_CONNECT, $context);
if (!$fp) {
    echo "Connection failed: $error_message ($error_code)\n";
    exit(1);
}

$params = stream_context_get_params($fp);
$params['ip'] = stream_socket_get_name($fp, true);

foreach ($params['options']['ssl']['peer_certificate_chain'] as $key => $value) {
    $params['options']['ssl']['peer_certificate_chain'][$key] = openssl_x509_parse($value);
}

$data = "HEAD / HTTP/1.1\r\nHost: $host\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
fwrite($fp, $data);
while (!feof($fp)) {
    $line = fgets($fp);
    if ($line === false || rtrim($line, "\r\n") === '') {
        break;
    }

    $header_line = trim($line);
    if (stripos($header_line, 'Server:') === 0) {
        $params['HTTP Server Header'] = trim(substr($header_line, 7));
    }
}

$json = json_encode($params, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
file_put_contents('cert.json', $json);
echo $json;
