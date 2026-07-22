<?php
// Usage: php -d extension=openssl check-host.php example.com json

/**
 * @param resource $fp
 * @param string $host
 * @return string|null
 */
function get_server_header($fp, string $host): ?string
{
    $data = "HEAD / HTTP/1.1\r\nHost: $host\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
    fwrite($fp, $data);
    while (!feof($fp)) {
        $line = fgets($fp);
        if ($line === false || rtrim($line, "\r\n") === '') {
            break;
        }

        $header_line = trim($line);
        if (stripos($header_line, 'Server:') === 0) {
            return trim(substr($header_line, 7));
        }
    }

    return null;
}

/**
 * @param array $params
 * @return string
 */
function render_html(array $params): string
{
    return "<h1>bla bla</h1>";
}

header('Access-Control-Allow-Origin: *');

$host = $_GET['host'] ?? $argv[1] ?? 'example.com';
$format = $_GET['format'] ?? $argv[2] ?? 'html';

$context = stream_context_create([
    'socket' => [
        'bindto' => '0.0.0.0:0', // IPv4
    ],
    'ssl' => [
        'peer_name' => $host,
        'capture_peer_cert_chain' => true,
        'verify_peer' => false,
        'verify_peer_name' => false,
    ],
]);

$fp = stream_socket_client("ssl://$host:443", $error_code, $error_message, null, STREAM_CLIENT_CONNECT, $context);
if (!$fp) {
    echo "Connection failed: $error_message ($error_code)\n";
    exit(1);
}

$params = stream_context_get_params($fp);
$name = stream_socket_get_name($fp, true);
if ($name) {
    $params['ip'] = explode(':', $name)[0];
}

foreach ($params['options']['ssl']['peer_certificate_chain'] as $key => $value) {
    $params['options']['ssl']['peer_certificate_chain'][$key] = openssl_x509_parse($value);
}

$params['HTTP Server Header'] = get_server_header($fp, $host);
$params['html'] = render_html($params);

if ($format === 'json') {
    header('Content-Type: application/json');
    echo json_encode($params, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} else {
    header('Content-Type: text/html');
    echo $params['html'];
}
