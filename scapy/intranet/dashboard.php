<?php
session_start();

if (!isset($_SESSION['username'])) {
    header('Location: index.php');
    exit();
}

$username = $_SESSION['username'];

$files = [
    'amuro' => [
        'amuro_report.txt' => 'Amuro Report',
        'amuro_data.txt' => 'Amuro Data',
        'amuro_secret.txt' => 'Amuro Secret'
    ],
    'char' => [
        'char_memo.txt' => 'Char Memo',
        'char_intelligence.txt' => 'Char Intelligence',
        'char_notes.txt' => 'Char Notes'
    ]
];

$userFiles = $files[$username] ?? [];
?>
<!DOCTYPE html>
<html>
<head>
    <title>Intranet Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #333;
            margin-top: 0;
        }
        .user-info {
            background-color: #e3f2fd;
            padding: 10px 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .user-info p {
            margin: 5px 0;
            color: #333;
        }
        h2 {
            color: #555;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }
        .file-list {
            list-style: none;
            padding: 0;
        }
        .file-item {
            padding: 12px;
            background-color: #f9f9f9;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .file-item:hover {
            background-color: #f0f0f0;
        }
        .file-name {
            color: #333;
        }
        .download-btn {
            padding: 8px 15px;
            background-color: #28a745;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .download-btn:hover {
            background-color: #218838;
        }
        .logout-btn {
            padding: 10px 20px;
            background-color: #dc3545;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            float: right;
            margin-top: 20px;
        }
        .logout-btn:hover {
            background-color: #c82333;
        }
        .clear {
            clear: both;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Company Intranet</h1>
        <div class="user-info">
            <p><strong>Logged in as:</strong> <?php echo htmlspecialchars($username); ?></p>
        </div>

        <h2>Available Files</h2>
        <ul class="file-list">
            <?php foreach ($userFiles as $filename => $displayName): ?>
                <li class="file-item">
                    <span class="file-name"><?php echo htmlspecialchars($displayName); ?></span>
                    <a href="download.php?file=<?php echo urlencode($filename); ?>" class="download-btn">Download</a>
                </li>
            <?php endforeach; ?>
        </ul>

        <a href="logout.php" class="logout-btn">Logout</a>
        <div class="clear"></div>
    </div>
</body>
</html>