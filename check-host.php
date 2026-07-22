<?php
// Usage: php -d extension=openssl check-host.php letsencrypt.org json

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

function get_ocsp_url(?string $aia): ?string
{
    if (!$aia) {
        return null;
    }
    foreach (preg_split('/\r?\n/', $aia) as $line) {
        if (stripos($line, 'OCSP') !== false && preg_match('/URI:(\S+)/i', $line, $m)) {
            return $m[1];
        }
    }
    return null;
}

function get_ocsp_staple(array $params): string
{
    $host = $params['options']['ssl']['peer_name'] ?? '';
    if ($host === '') {
        return 'Not Enabled';
    }

    $leaf = $params['options']['ssl']['peer_certificate_chain'][0] ?? null;
    // https://letsencrypt.org/2024/12/05/ending-ocsp
    if (!$leaf || $leaf['issuer']['O'] === "Let's Encrypt") {
        return 'Not Enabled';
    }

    $cmd = 'echo -n | openssl s_client -connect ' . escapeshellarg("$host:443") . ' -servername ' . escapeshellarg($host) . ' -status 2>&1';
    $out = shell_exec($cmd);
    if (!$out) {
        return 'Not Enabled';
    }
    if (stripos($out, 'OCSP Response Status: successful') !== false && preg_match('/Cert Status:\s*(\w+)/i', $out, $m)) {
        return ucfirst(strtolower($m[1]));
    }
    return 'Not Enabled';
}

function get_ocsp_origin(array $params): string
{
    $leaf = $params['options']['ssl']['peer_certificate_chain'][0] ?? null;
    // https://letsencrypt.org/2024/12/05/ending-ocsp
    if (!$leaf || $leaf['issuer']['O'] === "Let's Encrypt") {
        return 'Not Enabled';
    }

    $issuer = $params['options']['ssl']['peer_certificate_chain'][1] ?? null;

    $leafPem = $leaf['pem'] ?? null;
    $issuerPem = $issuer['pem'] ?? null;

    $aia = $leaf['extensions']['authorityInfoAccess'] ?? '';
    $ocspUrl = get_ocsp_url($aia);

    if (!$ocspUrl || !$leafPem || !$issuerPem) {
        return '';
    }

    $leafFile = tempnam(sys_get_temp_dir(), 'leaf_');
    $issuerFile = tempnam(sys_get_temp_dir(), 'issuer_');
    file_put_contents($leafFile, $leafPem);
    file_put_contents($issuerFile, $issuerPem);

    $ocspHost = parse_url($ocspUrl, PHP_URL_HOST);
    $cmd = 'openssl ocsp -issuer ' . escapeshellarg($issuerFile)
        . ' -cert ' . escapeshellarg($leafFile)
        . ' -url ' . escapeshellarg($ocspUrl)
        . ($ocspHost ? ' -header ' . escapeshellarg('Host=' . $ocspHost) : '')
        . ' -no_nonce -text 2>&1';
    $out = shell_exec($cmd);
    @unlink($leafFile);
    @unlink($issuerFile);

    if (!$out) {
        return '';
    }
    if (preg_match('/:\s*good\b/i', $out)) {
        return 'Good';
    }
    if (preg_match('/:\s*revoked\b/i', $out)) {
        return 'Revoked';
    }
    if (preg_match('/:\s*unknown\b/i', $out)) {
        return 'Unknown';
    }

    return '';
}

function get_crl_status(array $params): string
{
    $leaf = $params['options']['ssl']['peer_certificate_chain'][0] ?? null;
    if (!$leaf) {
        return 'Not Enabled';
    }

    $serialHex = $leaf['serialNumberHex'] ?? (isset($leaf['serialNumber']) ? strtoupper(dechex((int) $leaf['serialNumber'])) : '');
    if ($serialHex === '') {
        return 'Not Enabled';
    }

    $crlExt = $leaf['extensions']['crlDistributionPoints'] ?? '';
    $urls = [];
    if ($crlExt && preg_match_all('/URI:(\S+)/i', $crlExt, $m)) {
        $urls = $m[1];
    }

    if (empty($urls)) {
        return 'Not Enabled';
    }

    $maxBytes = 8 * 1024 * 1024; // 8MB limit

    foreach ($urls as $url) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT      => 'Mozilla/5.0',
        ]);
        $data = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

        if ($data === false || $httpCode !== 200 || strlen($data) >= $maxBytes) {
            continue;
        }

        $tmp = tempnam(sys_get_temp_dir(), 'crl_');
        if ($tmp === false) {
            continue;
        }
        file_put_contents($tmp, $data);

        $output = shell_exec('openssl crl -inform DER -in ' . escapeshellarg($tmp) . ' -noout -text');
        if (!$output) {
            $output = shell_exec('openssl crl -inform PEM -in ' . escapeshellarg($tmp) . ' -noout -text');
        }
        @unlink($tmp);

        if (!$output) {
            continue;
        }

        return (stripos($output, $serialHex) !== false) ? 'Revoked' : 'Good';
    }

    return 'Not Enabled';
}

/**
 * @param array $params
 * @return string
 */
function render_html(array $params): string
{
    return <<<EOF

EOF;
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
    $parsed = openssl_x509_parse($value);
    if ($parsed && openssl_x509_export($value, $pem)) {
        $parsed['pem'] = $pem;
    }
    $params['options']['ssl']['peer_certificate_chain'][$key] = $parsed;
}

$params['HTTP Server Header'] = get_server_header($fp, $host);
$params['ocsp_staple'] = get_ocsp_staple($params);
$params['ocsp_origin'] = get_ocsp_origin($params);
$params['crl_status'] = get_crl_status($params);
$params['html'] = render_html($params);

if ($format === 'json') {
    header('Content-Type: application/json');
    echo json_encode($params, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    file_put_contents('cert.json', json_encode($params, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
} else {
    header('Content-Type: text/html');
    echo $params['html'];
}
