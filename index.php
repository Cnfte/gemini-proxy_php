<?php

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

set_time_limit(0);
ignore_user_abort(true);

ini_set('memory_limit', '-1');

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key, X-Requested-With, User-Agent, Accept, Origin, Cache-Control, X-Request-ID, X-Goog-Api-Key, X-Session-Token, X-Client-Version, X-Device-Id");
header("Access-Control-Max-Age: 86400");
header("Access-Control-Expose-Headers: X-Request-ID, X-Response-Time");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit(0);
}

define('UPSTREAM_HOST', 'https://generativelanguage.googleapis.com');
define('DEFAULT_API_VERSION', 'v1beta');
define('DEBUG_MODE', isset($_GET['debug']) || (isset($_SERVER['HTTP_DEBUG']) && $_SERVER['HTTP_DEBUG'] === 'true'));
define('REQUEST_TIMEOUT', 0);

$start_time = microtime(true);

function debug_log($message, $data = null) {
    if (!DEBUG_MODE) return;
    $log_data = [
        'timestamp' => date('Y-m-d H:i:s'),
        'message' => $message
    ];
    if ($data !== null) {
        $log_data['data'] = $data;
    }
    error_log('GEMINI_PROXY: ' . json_encode($log_data, JSON_UNESCAPED_UNICODE));
}

function send_json_response($code, $data, $headers = []) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    
    $request_id = uniqid('gemini_proxy_', true);
    header('X-Request-ID: ' . $request_id);
    
    global $start_time;
    $response_time = round((microtime(true) - $start_time) * 1000, 2);
    header('X-Response-Time: ' . $response_time . 'ms');
    
    foreach ($headers as $key => $value) {
        header("$key: $value");
    }
    
    if (is_array($data) && !isset($data['request_id'])) {
        $data['request_id'] = $request_id;
    }
    
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit(0);
}

function get_all_headers() {
    $headers = [];
    
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        $normalized = [];
        foreach ($headers as $key => $value) {
            $normalized[strtolower($key)] = $value;
        }
        return $normalized;
    }
    
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
            $headers[strtolower($name)] = $value;
        }
    }
    
    $special = ['content-type', 'content-length', 'authorization'];
    foreach ($special as $header) {
        $server_key = strtoupper(str_replace('-', '_', $header));
        if (isset($_SERVER[$server_key])) {
            $headers[$header] = $_SERVER[$server_key];
        }
    }
    
    return $headers;
}

function extract_api_key($headers) {
    if (isset($headers['x-goog-api-key'])) {
        $api_key = trim($headers['x-goog-api-key']);
        if (!empty($api_key)) return $api_key;
    }
    
    if (isset($headers['authorization'])) {
        $auth = trim($headers['authorization']);
        if (preg_match('/^Bearer\s+(.+)$/i', $auth, $m)) {
            return trim($m[1]);
        }
        if (!empty($auth) && !preg_match('/\s/', $auth)) {
            return $auth;
        }
    }
    
    $query_keys = ['key', 'api_key', 'apikey', 'token', 'access_token'];
    foreach ($query_keys as $key) {
        if (isset($_GET[$key])) {
            $val = trim($_GET[$key]);
            if (!empty($val)) return $val;
        }
    }
    
    return null;
}

function get_request_path() {
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $path = parse_url($uri, PHP_URL_PATH) ?? '/';
    
    $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
    if ($script_name && strpos($path, $script_name) === 0) {
        $path = substr($path, strlen($script_name));
    }
    
    $path = preg_replace('#/index\.php#i', '', $path);
    $path = '/' . trim($path, '/');
    return $path === '' ? '/' : $path;
}

function needs_version_downgrade($body) {
    if (empty($body)) return false;
    
    $data = json_decode($body, true);
    if (json_last_error() !== JSON_ERROR_NONE) return false;
    
    $unsupported_in_v1 = ['systemInstruction', 'tool_config', 'tool_calls'];
    
    foreach ($unsupported_in_v1 as $param) {
        if (isset($data[$param])) {
            return true;
        }
        
        if (isset($data['contents']) && is_array($data['contents'])) {
            foreach ($data['contents'] as $content) {
                if (isset($content['parts']) && is_array($content['parts'])) {
                    foreach ($content['parts'] as $part) {
                        if (isset($part[$param])) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    
    return false;
}

function make_body_compatible($body, $target_version) {
    if (empty($body) || $target_version !== 'v1') return $body;
    
    $data = json_decode($body, true);
    if (json_last_error() !== JSON_ERROR_NONE) return $body;
    
    $unsupported_fields = ['systemInstruction', 'tool_config', 'tool_calls'];
    
    $remove_unsupported_fields = function(&$array) use ($unsupported_fields, &$remove_unsupported_fields) {
        foreach ($unsupported_fields as $field) {
            if (isset($array[$field])) {
                unset($array[$field]);
            }
        }
        
        foreach ($array as &$value) {
            if (is_array($value)) {
                $remove_unsupported_fields($value);
            }
        }
    };
    
    $remove_unsupported_fields($data);
    
    return json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

function build_gemini_path($path) {
    if (preg_match('#^/(v1|v1beta)/#', $path, $matches)) {
        $current_version = $matches[1];
        return $path;
    }
    
    return '/' . DEFAULT_API_VERSION . $path;
}

function get_target_api_version($path, $body) {
    if (preg_match('#^/(v1|v1beta)/#', $path, $matches)) {
        return $matches[1];
    }
    
    if (needs_version_downgrade($body)) {
        return 'v1beta';
    }
    
    return DEFAULT_API_VERSION;
}

function get_request_body() {
    return file_get_contents('php://input');
}

try {
    $headers = get_all_headers();
    $api_key = extract_api_key($headers);
    $method = strtoupper($_SERVER['REQUEST_METHOD']);
    $path = get_request_path();
    $body = get_request_body();

    debug_log('请求详情', [
        'method' => $method,
        'path' => $path,
        'api_key_found' => !empty($api_key),
        'body_length' => strlen($body)
    ]);

    if (DEBUG_MODE) {
        send_json_response(200, [
            'debug' => true,
            'method' => $method,
            'path' => $path,
            'api_key_found' => !empty($api_key),
            'body_length' => strlen($body),
            'needs_downgrade' => needs_version_downgrade($body),
            'server_info' => [
                'php_version' => PHP_VERSION,
                'memory_usage' => memory_get_usage(true),
                'memory_peak' => memory_get_peak_usage(true),
                'max_execution_time' => ini_get('max_execution_time'),
                'memory_limit' => ini_get('memory_limit')
            ]
        ]);
    }

    if (empty($api_key)) {
        send_json_response(401, [
            'error' => [
                'code' => 401,
                'message' => 'API key not found',
                'status' => 'UNAUTHENTICATED'
            ]
        ]);
    }

    $target_version = get_target_api_version($path, $body);
    $compatible_body = make_body_compatible($body, $target_version);
    
    $target_path = build_gemini_path($path);
    
    if (!preg_match('#^/(v1|v1beta)/#', $target_path)) {
        $target_path = '/' . $target_version . $path;
    }

    debug_log('版本兼容性处理', [
        'original_path' => $path,
        'target_version' => $target_version,
        'target_path' => $target_path,
        'body_modified' => ($body !== $compatible_body)
    ]);

    $target_url = UPSTREAM_HOST . $target_path;
    $query_params = ['key' => $api_key];
    
    $original_query = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_QUERY);
    if ($original_query) {
        parse_str($original_query, $original_params);
        $skip_params = ['key', 'api_key', 'apikey', 'token', 'access_token', 'debug'];
        foreach ($original_params as $key => $value) {
            if (!in_array($key, $skip_params)) {
                $query_params[$key] = $value;
            }
        }
    }
    
    $target_url .= (strpos($target_url, '?') === false ? '?' : '&') . http_build_query($query_params);

    $upstream_headers = [];
    $skip_headers = ['host', 'connection', 'content-length', 'x-goog-api-key', 'authorization', 'x-api-key', 'api-key'];

    foreach ($headers as $key => $value) {
        $lower_key = strtolower($key);
        if (in_array($lower_key, $skip_headers)) continue;
        $upstream_headers[] = "$key: $value";
    }

    if (in_array($method, ['POST', 'PUT', 'PATCH']) && !empty($compatible_body)) {
        $has_content_type = false;
        foreach ($upstream_headers as $header) {
            if (stripos($header, 'content-type:') === 0) {
                $has_content_type = true;
                break;
            }
        }
        if (!$has_content_type) {
            $upstream_headers[] = 'Content-Type: application/json';
        }
    }

    debug_log('转发请求', [
        'url' => str_replace($api_key, '***', $target_url),
        'version' => $target_version,
        'headers_count' => count($upstream_headers)
    ]);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $target_url,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $upstream_headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => REQUEST_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => 0,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_ENCODING => '',
        CURLOPT_USERAGENT => 'Gemini-API-Proxy/No-Limits',
        CURLOPT_BUFFERSIZE => 128000,
        CURLOPT_NOPROGRESS => false,
        CURLOPT_TCP_KEEPALIVE => 1,
        CURLOPT_TCP_KEEPIDLE => 120,
        CURLOPT_TCP_KEEPINTVL => 60
    ]);

    if (in_array($method, ['POST', 'PUT', 'PATCH']) && !empty($compatible_body)) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $compatible_body);
        curl_setopt($ch, CURLOPT_INFILESIZE, strlen($compatible_body));
    }

    $response = curl_exec($ch);

    if ($response === false) {
        $error = curl_error($ch);
        $errno = curl_errno($ch);
        curl_close($ch);
        
        debug_log('CURL 错误', ['error' => $error, 'errno' => $errno]);
        
        send_json_response(502, [
            'error' => [
                'code' => 502,
                'message' => 'Failed to connect to Google Gemini API: ' . $error,
                'status' => 'BAD_GATEWAY',
                'details' => [
                    'curl_error' => $error,
                    'curl_errno' => $errno
                ]
            ]
        ]);
    }

    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $total_time = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
    curl_close($ch);

    $response_headers = substr($response, 0, $header_size);
    $response_body = substr($response, $header_size);

    debug_log('收到响应', [
        'http_code' => $http_code,
        'header_size' => $header_size,
        'body_size' => strlen($response_body),
        'total_time' => $total_time
    ]);

    if ($http_code >= 400) {
        debug_log('API 错误响应', [
            'http_code' => $http_code,
            'response_preview' => substr($response_body, 0, 1000)
        ]);
    }

    $safe_headers = [
        'content-type', 'content-encoding', 'cache-control',
        'expires', 'last-modified', 'etag', 'vary',
        'x-goog-generation', 'x-goog-metageneration', 'x-goog-stored-content-encoding',
        'x-goog-stored-content-length', 'x-goog-hash', 'x-guploader-uploadid'
    ];

    $header_lines = preg_split('/\r\n|\n|\r/', $response_headers);
    foreach ($header_lines as $line) {
        $line = trim($line);
        if (empty($line) || strpos($line, 'HTTP/') === 0) continue;
        
        $colon = strpos($line, ':');
        if ($colon === false) continue;
        
        $name = strtolower(substr($line, 0, $colon));
        $value = trim(substr($line, $colon + 1));
        
        if (in_array($name, $safe_headers)) {
            header("$name: $value", false);
        }
    }

    header('X-Proxy-Request-ID: ' . uniqid('proxy_', true));
    header('X-Upstream-Response-Time: ' . round($total_time * 1000, 2) . 'ms');
    header('X-Proxy-Memory-Usage: ' . memory_get_usage(true));

    http_response_code($http_code);
    echo $response_body;

} catch (Exception $e) {
    debug_log('代理错误', [
        'error' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine()
    ]);
    send_json_response(500, [
        'error' => [
            'code' => 500,
            'message' => 'Internal server error in proxy: ' . $e->getMessage()
        ]
    ]);
} catch (Throwable $e) {
    debug_log('严重错误', [
        'error' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine()
    ]);
    send_json_response(500, [
        'error' => [
            'code' => 500,
            'message' => 'Fatal error in proxy'
        ]
    ]);
}

while (ob_get_level() > 0) {
    ob_end_flush();
}
flush();

exit(0);
