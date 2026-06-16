<?php
session_start();

if (!isset($_SESSION['username'])) {
    header('Location: index.php');
    exit();
}

$username = $_SESSION['username'];
$requestedFile = $_GET['file'] ?? '';

$files = [
    'amuro' => [
        'amuro_report.txt',
        'amuro_data.txt',
        'amuro_secret.txt'
    ],
    'char' => [
        'char_memo.txt',
        'char_intelligence.txt',
        'char_notes.txt'
    ]
];

$userFiles = $files[$username] ?? [];

if (!in_array($requestedFile, $userFiles)) {
    header('HTTP/1.0 403 Forbidden');
    echo 'Access denied';
    exit();
}

$filePath = __DIR__ . '/' . $requestedFile;

if (!file_exists($filePath)) {
    header('HTTP/1.0 404 Not Found');
    echo 'File not found';
    exit();
}

// Disable any output compression so Content-Length matches the raw file size
// and the interceptor (or any sniffer) sees uncompressed bytes.
ini_set('zlib.output_compression', '0');
if (ob_get_level()) ob_end_clean();

header('Content-Type: text/plain');
header('Content-Encoding: identity');
header('Content-Disposition: attachment; filename="' . $requestedFile . '"');
header('Content-Length: ' . filesize($filePath));

readfile($filePath);
exit();
?>