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
        return '';
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

    if (!is_array($leaf)) {
        $leaf = openssl_x509_parse($leaf) ?: [];
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
    $cacheDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'crl_cache';
    if (!is_dir($cacheDir)) {
        @mkdir($cacheDir, 0755, true);
    }

    foreach ($urls as $url) {
        $cacheFile = $cacheDir . DIRECTORY_SEPARATOR . md5($url) . '.cache';
        $output = false;

        if (file_exists($cacheFile)) {
            $content = file_get_contents($cacheFile);
            if ($content !== false) {
                $pos = strpos($content, "\n");
                if ($pos !== false) {
                    $expireTimestamp = (int) substr($content, 0, $pos);
                    if ($expireTimestamp > time()) {
                        $output = substr($content, $pos + 1);
                    }
                }
            }
        }

        if ($output === false) {
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

            $opensslCmd = 'openssl';
            if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                if (file_exists('C:\\Program Files\\Git\\usr\\bin\\openssl.exe')) {
                    $opensslCmd = '"C:\\Program Files\\Git\\usr\\bin\\openssl.exe"';
                }
            }

            $res = shell_exec($opensslCmd . ' crl -inform DER -in ' . escapeshellarg($tmp) . ' -noout -text 2>&1');
            if (!$res || stripos((string) $res, 'Certificate Revocation List') === false) {
                $res = shell_exec($opensslCmd . ' crl -inform PEM -in ' . escapeshellarg($tmp) . ' -noout -text 2>&1');
            }
            @unlink($tmp);

            if (is_array($res)) {
                $res = implode("\n", $res);
            }

            if (!$res || !is_string($res)) {
                continue;
            }

            $output = $res;

            $expireTimestamp = 0;
            if (preg_match('/Next Update:\s*(.+)$/im', $output, $matches)) {
                $parsedTime = strtotime(trim($matches[1]));
                if ($parsedTime !== false && $parsedTime > time()) {
                    $expireTimestamp = $parsedTime;
                }
            }
            if ($expireTimestamp <= time()) {
                $expireTimestamp = time() + 21600; // fallback 6 hours
            }

            file_put_contents($cacheFile, $expireTimestamp . "\n" . $output);
        }

        if (is_string($output)) {
            return (stripos($output, $serialHex) !== false) ? 'Revoked' : 'Good';
        }
    }

    return 'Not Enabled';
}

function h(string|int|float|null $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

function sig_alg_display(string $sn): string
{
    if ($sn === '') {
        return '';
    }
    if (stripos($sn, 'ed25519') !== false) {
        return 'ED25519';
    }
    if (stripos($sn, 'ed448') !== false) {
        return 'ED448';
    }

    $hash = '';
    $hashPos = null;
    if (preg_match('/sha(1|224|256|384|512)/i', $sn, $m, PREG_OFFSET_CAPTURE)) {
        $hash = 'SHA' . $m[1][0];
        $hashPos = $m[0][1];
    }

    $algo = '';
    $algoPos = null;
    if (stripos($sn, 'pss') !== false && preg_match('/rsa/i', $sn, $m2, PREG_OFFSET_CAPTURE)) {
        $algo = 'RSA-PSS';
        $algoPos = $m2[0][1];
    } elseif (preg_match('/ecdsa/i', $sn, $m2, PREG_OFFSET_CAPTURE)) {
        $algo = 'ECDSA';
        $algoPos = $m2[0][1];
    } elseif (preg_match('/rsa/i', $sn, $m2, PREG_OFFSET_CAPTURE)) {
        $algo = 'RSA';
        $algoPos = $m2[0][1];
    } elseif (preg_match('/dsa/i', $sn, $m2, PREG_OFFSET_CAPTURE)) {
        $algo = 'DSA';
        $algoPos = $m2[0][1];
    }

    if ($hash === '' && $algo === '') {
        return strtoupper($sn);
    }
    if ($hash === '') {
        return $algo;
    }
    if ($algo === '') {
        return $hash;
    }

    return ($hashPos <= $algoPos) ? ($hash . '-' . $algo) : ($algo . '-' . $hash);
}

function get_signature_algorithm(array $parsed): string
{
    return $parsed['signatureTypeLN'] ?? $parsed['signatureTypeSN'] ?? '';
}

function get_san_list(array $extensions): array
{
    $sans = [];
    if (!empty($extensions['subjectAltName'])) {
        foreach (explode(',', $extensions['subjectAltName']) as $part) {
            $part = trim($part);
            if (stripos($part, 'DNS:') === 0) {
                $sans[] = substr($part, 4);
            }
        }
    }
    return $sans;
}

function name_matches(string $host, string $pattern): bool
{
    $host = strtolower($host);
    $pattern = strtolower($pattern);
    if ($pattern === $host) {
        return true;
    }
    if (strpos($pattern, '*.') === 0) {
        $suffix = substr($pattern, 1);
        if (substr($host, -strlen($suffix)) === $suffix && substr_count($host, '.') === substr_count($pattern, '.')) {
            return true;
        }
    }
    return false;
}

function host_matches(string $host, string $cn, array $sans): bool
{
    $names = $sans;
    if ($cn !== '' && !in_array($cn, $names, true)) {
        $names[] = $cn;
    }
    foreach ($names as $name) {
        if (name_matches($host, $name)) {
            return true;
        }
    }
    return false;
}

function format_serial_hex(string $hex, bool $preserveRaw): string
{
    if ($preserveRaw) {
        return $hex;
    }
    $stripped = ltrim($hex, '0');
    return $stripped === '' ? '0' : $stripped;
}

function raw_bit_length(?string $bin): int
{
    if ($bin === null) {
        return 0;
    }
    $bin = ltrim($bin, "\x00");
    if ($bin === '') {
        return 0;
    }
    $len = strlen($bin) * 8;
    $firstByte = ord($bin[0]);
    $mask = 0x80;
    while ($mask > 0 && ($firstByte & $mask) === 0) {
        $len--;
        $mask >>= 1;
    }
    return $len;
}

function cert_info_from_parsed(array $parsed): array
{
    $pem = $parsed['pem'] ?? '';
    $pubkey = $pem !== '' ? openssl_pkey_get_public($pem) : false;
    $keyDetails = $pubkey ? openssl_pkey_get_details($pubkey) : null;
    $serialHex = $parsed['serialNumberHex'] ?? (isset($parsed['serialNumber']) ? strtoupper(dechex((int) $parsed['serialNumber'])) : '');

    $keyBits = $keyDetails['bits'] ?? '';
    if ($keyDetails && $keyDetails['type'] === OPENSSL_KEYTYPE_EC && !empty($keyDetails['ec']['x'])) {
        $keyBits = raw_bit_length($keyDetails['ec']['x']);
    }

    return [
        'pem'         => $pem,
        'subject_cn'  => $parsed['subject']['CN'] ?? '',
        'subject_o'   => $parsed['subject']['O'] ?? '',
        'subject_l'   => $parsed['subject']['L'] ?? '',
        'subject_st'  => $parsed['subject']['ST'] ?? '',
        'subject_c'   => $parsed['subject']['C'] ?? '',
        'issuer_cn'   => $parsed['issuer']['CN'] ?? '',
        'not_before'  => $parsed['validFrom_time_t'] ?? 0,
        'not_after'   => $parsed['validTo_time_t'] ?? 0,
        'serial_hex'  => strtoupper($serialHex),
        'sha1'        => $pem !== '' ? strtoupper((string) openssl_x509_fingerprint($pem, 'sha1')) : '',
        'key_bits'    => $keyBits,
        'sig_alg'     => get_signature_algorithm($parsed),
        'extensions'  => $parsed['extensions'] ?? [],
        'self_signed' => ($parsed['subject'] ?? null) === ($parsed['issuer'] ?? null),
    ];
}

/**
 * @param array $params
 * @return string
 */
function render_html(array $params): string
{
    $host = $params['options']['ssl']['peer_name'] ?? '';
    $hostEsc = h($host);
    $ip = $params['ip'] ?? '';

    $html = '';

    // 1. DNS resolution
    if ($ip !== '') {
        $html .= '<h2 class="ok">DNS resolves ' . $hostEsc . ' to ' . h($ip) . '</h2>';
    }

    // 2. HTTP Server header
    $serverHeader = $params['HTTP Server Header'] ?? null;
    if ($serverHeader !== null && $serverHeader !== '') {
        $html .= '<p>HTTP Server Header: ' . h($serverHeader) . '</p>';
    }

    // 3. Certificate chain & details
    $chain = $params['options']['ssl']['peer_certificate_chain'] ?? [];
    if (empty($chain)) {
        return $html;
    }

    $certs = array_map('cert_info_from_parsed', $chain);
    $leaf = $certs[0];
    $sans = get_san_list($leaf['extensions']);
    $sanDisplay = !empty($sans) ? implode(', ', $sans) : $leaf['subject_cn'];

    $hasDigicertBrand = false;
    foreach ($certs as $info) {
        if (stripos($info['subject_cn'], 'digicert') !== false) {
            $hasDigicertBrand = true;
            break;
        }
    }

    $html .= '<div id="CertDetails">';
    $html .= '<p>Common Name = ' . h($leaf['subject_cn']) . '</p>';
    if ($leaf['subject_o'] !== '') {
        $html .= '<p>Organization = ' . h($leaf['subject_o']) . '</p>';
    }
    if ($leaf['subject_l'] !== '') {
        $html .= '<p>City/Locality = ' . h($leaf['subject_l']) . '</p>';
    }
    if ($leaf['subject_st'] !== '') {
        $html .= '<p>State/Province = ' . h($leaf['subject_st']) . '</p>';
    }
    if ($leaf['subject_c'] !== '') {
        $html .= '<p>Country = ' . h($leaf['subject_c']) . '</p>';
    }
    $html .= '<p>Subject Alternative Names = ' . h($sanDisplay) . '</p>';
    $html .= '<p>Issuer = ' . h($leaf['issuer_cn']) . '</p>';
    $html .= '<p>Serial Number = ' . h(format_serial_hex($leaf['serial_hex'], $hasDigicertBrand)) . '</p>';
    $html .= '<p>SHA1 Thumbprint = ' . h($leaf['sha1']) . '</p>';
    $html .= '<p>Key Length = ' . h($leaf['key_bits']) . '</p>';
    $html .= '<p>Signature algorithm = ' . h(sig_alg_display($leaf['sig_alg'])) . '</p>';
    $html .= '<p>Secure Renegotiation: </p>';
    $html .= '</div>' . "\n";

    // 4. Revocation status (OCSP staple / OCSP origin / CRL)
    $staple = $params['ocsp_staple'] ?? 'Not Enabled';
    $origin = $params['ocsp_origin'] ?? '';
    $crl = $params['crl_status'] ?? 'Not Enabled';

    $revoked = (stripos($staple, 'revoked') !== false)
        || (stripos($origin, 'revoked') !== false)
        || (stripos($crl, 'revoked') !== false);

    if ($origin === '') {
        $html .= '<h2 class="warning">TLS Certificate status cannot be validated</h2>';
    } elseif ($revoked) {
        $html .= '<h2 class="error">TLS Certificate has been revoked</h2>';
    } else {
        $html .= '<h2 class="ok">TLS Certificate has not been revoked</h2>';
    }
    $html .= '<table>';
    $html .= '<tr><td>OCSP Staple: </td><td>' . h($staple) . '</td></tr>';
    $html .= '<tr><td>OCSP Origin: </td><td>' . h($origin) . '</td></tr>';
    $html .= '<tr><td>CRL Status: </td><td>' . h($crl) . '</td></tr>';
    $html .= '</table><br />';

    // 5. Expiration
    $now = time();
    $daysLeft = (int) floor(($leaf['not_after'] - $now) / 86400);
    $expired = $daysLeft < 0;
    $expDateStr = date('F j, Y', $leaf['not_after']);

    if ($expired) {
        $days = abs($daysLeft);
        $expMsg = 'The certificate expired ' . $expDateStr . ' (' . $days . ' day' . ($days === 1 ? '' : 's') . ' ago)';
    } else {
        $expMsg = 'The certificate expires ' . $expDateStr . ' (' . $daysLeft . ' day' . ($daysLeft === 1 ? '' : 's') . ' from today)';
    }

    $html .= '<h2 class="' . ($expired ? 'error' : 'ok') . '">TLS Certificate expiration</h2>';
    $html .= '<p>' . $expMsg . '</p>';

    // 6. Certificate name match
    $nameOk = host_matches($host, $leaf['subject_cn'], $sans);
    $html .= '<h2 class="' . ($nameOk ? 'ok' : 'error') . '">Certificate Name ' . ($nameOk ? 'matches' : 'does not match') . ' ' . $hostEsc . '</h3>';

    // 7. Certificate chain table
    $html .= '<div id="chain"><table>' . "\n";
    $n = count($certs);
    foreach ($certs as $i => $info) {
        $brand = (stripos($info['subject_cn'], 'digicert') !== false) ? 'digicert' : 'generic';
        $icon = $brand . '-' . ($i === 0 ? 'server-cert.gif' : 'intermediate-cert.gif');
        $validFrom = date('d/M/Y', $info['not_before']);
        $validTo = date('d/M/Y', $info['not_after']);

        $html .= '<tr><td rowspan="4" style="text-align: center;"><img src="/images/icons/' . $icon . '" style="border: 0"/></td>'
            . '<tr><td>Subject</td><td>' . h($info['subject_cn']) . '</td></tr>'
            . '<tr><td colspan="2">Valid from ' . $validFrom . ' to ' . $validTo . '</td></tr>'
            . '<tr><td>Issuer</td><td>' . h($info['issuer_cn']) . '</td></tr>';

        if ($i < $n - 1) {
            $html .= '<tr><td style="text-align: center"><img src="/images/icons/chain-good.gif" /></td><td colspan="2">&nbsp;</td></tr>';
        }
        $html .= "\n";
    }
    $html .= '</table></div>';

    // 8. Overall result
    $allOk = !$revoked && !$expired && $nameOk;

    if ($allOk) {
        $html .= '<h2 class="ok" style="margin-top:18px;">TLS Certificate is correctly installed</h2>' . "\n";
        $html .= '<p>Congratulations! This certificate is correctly installed.</p>' . "\n";
    } else {
        $html .= '<h2 class="error" style="margin-top:18px;">TLS Certificate is NOT correctly installed</h2>' . "\n";
        $html .= '<p>Please review the issues listed above.</p>' . "\n";
    }

    return $html;
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
