<?php
require_once __DIR__ . '/../api/auth.php';
require_once __DIR__ . '/../api/db.php';
require_once __DIR__ . '/../api/csrf.php';
require_once __DIR__ . '/../api/security_bridge.php';
require_manager();

$auditLog = __DIR__ . '/../logs/manager_audit.log';
if (!is_dir(dirname($auditLog))) {
    mkdir(dirname($auditLog), 0755, true);
}

function audit($action, $extra = '') {
    global $auditLog;
    $entry = sprintf(
        "[%s] Manager: %s (ID:%s) | IP: %s | Action: %s%s\n",
        date('Y-m-d H:i:s'),
        $_SESSION['name']    ?? 'unknown',
        $_SESSION['user_id'] ?? '?',
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $action,
        $extra ? " | $extra" : ''
    );
    file_put_contents($auditLog, $entry, FILE_APPEND | LOCK_EX);
}

audit('Dashboard Access');

if (isset($_POST['unban_ip'])) {
    // CSRF Protection
    if (!csrf_verify()) {
        http_response_code(403);
        die('<p style="color:red;font-family:sans-serif;padding:20px;">&#9888; Invalid security token. <a href="manager.php">Go back</a></p>');
    }
    $ip = trim($_POST['unban_ip']);
    unban_ip_db($pdo, $ip);
    audit('UNBAN', "Target IP: $ip");
    header("Location: manager.php");
    exit;
}

$bans_response = security_get('/ban/list');
$bans = $bans_response['bans'] ?? [];

$report = security_get('/report/summary') ?? [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWU Shopping - Manager Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; color: #333; }

        .header {
            background: #2b3445;
            color: white;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 20px; }
        .header a {
            color: #e74c3c;
            text-decoration: none;
            border: 1px solid #e74c3c;
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 13px;
        }

        .container { padding: 30px; max-width: 1200px; margin: auto; }

        /* Stats Cards */
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        .stat-card .icon { font-size: 30px; margin-bottom: 10px; }
        .stat-card .number { font-size: 28px; font-weight: 700; color: #2b3445; }
        .stat-card .label { font-size: 13px; color: #888; margin-top: 4px; }
        .stat-card.danger .number { color: #e74c3c; }
        .stat-card.warning .number { color: #f39c12; }
        .stat-card.success .number { color: #27ae60; }

        /* Threat Level */
        .threat-badge {
            display: inline-block;
            padding: 4px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
        }
        .threat-LOW { background: #d5f5e3; color: #27ae60; }
        .threat-MEDIUM { background: #fef9e7; color: #f39c12; }
        .threat-HIGH { background: #fdebd0; color: #e67e22; }
        .threat-CRITICAL { background: #fadbd8; color: #e74c3c; }

        /* Table */
        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            margin-bottom: 24px;
        }
        .card h2 {
            font-size: 18px;
            margin-bottom: 18px;
            color: #2b3445;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th {
            text-align: left;
            padding: 10px 14px;
            background: #f8f9fa;
            color: #666;
            font-weight: 500;
            font-size: 12px;
            border-bottom: 1px solid #eee;
        }
        td { padding: 12px 14px; border-bottom: 1px solid #f0f0f0; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #fafafa; }

        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }
        .badge-danger { background: #fadbd8; color: #e74c3c; }
        .badge-warning { background: #fef9e7; color: #f39c12; }

        .unban-btn {
            background: #27ae60;
            color: white;
            border: none;
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            transition: 0.2s;
        }
        .unban-btn:hover { background: #229954; }

        .empty { text-align: center; color: #aaa; padding: 30px; font-size: 14px; }
    </style>
</head>
<body>

<div class="header">
    <h1><i class="fa-solid fa-shield-halved"></i> AWU Shopping — Manager Dashboard</h1>
    <div style="display:flex;gap:10px;align-items:center;">
        <span style="font-size:14px;">👋 <?= htmlspecialchars($_SESSION['name']) ?></span>
        <a href="../api/logout.php">Logout</a>
    </div>
</div>

<div class="container">

    <div class="stats">
        <div class="stat-card danger">
            <div class="icon">⚔️</div>
            <div class="number"><?= $report['total_attacks'] ?? 0 ?></div>
            <div class="label">Total Attacks (24h)</div>
        </div>
        <div class="stat-card warning">
            <div class="icon">🚫</div>
            <div class="number"><?= count($bans) ?></div>
            <div class="label">Active Bans</div>
        </div>
        <div class="stat-card danger">
            <div class="icon">🔨</div>
            <div class="number"><?= $report['brute_force_bans'] ?? 0 ?></div>
            <div class="label">Brute Force Bans</div>
        </div>
        <div class="stat-card">
            <div class="icon">🛡️</div>
            <div class="number">
                <span class="threat-badge threat-<?= $report['threat_level'] ?? 'LOW' ?>">
                    <?= $report['threat_level'] ?? 'LOW' ?>
                </span>
            </div>
            <div class="label">Threat Level</div>
        </div>
    </div>

    <div class="card">
        <h2><i class="fa-solid fa-ban" style="color:#e74c3c"></i> Banned IP Addresses</h2>
        <?php if (empty($bans)): ?>
            <div class="empty">✅ No active bans at the moment.</div>
        <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>IP Address</th>
                    <th>Reason</th>
                    <th>Banned At</th>
                    <th>Until</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($bans as $i => $ban): ?>
                <tr>
                    <td><?= $i + 1 ?></td>
                    <td><strong><?= htmlspecialchars($ban['ip']) ?></strong></td>
                    <td>
                        <span class="badge badge-danger">
                            <?= htmlspecialchars($ban['reason']) ?>
                        </span>
                    </td>
                    <td><?= htmlspecialchars($ban['created'] ?? $ban['banned_at'] ?? 'N/A') ?></td>
                    <td>
                        <?php if ($ban['until'] === 'permanent'): ?>
                            <span class="badge badge-danger">Permanent</span>
                        <?php else: ?>
                            <span class="badge badge-warning"><?= htmlspecialchars($ban['until']) ?></span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <form method="POST" onsubmit="return confirm('Unban <?= htmlspecialchars($ban['ip']) ?>?')">
                            <?= csrf_field() ?>
                            <input type="hidden" name="unban_ip" value="<?= htmlspecialchars($ban['ip']) ?>">
                            <button type="submit" class="unban-btn">
                                <i class="fa-solid fa-unlock"></i> Unban
                            </button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>

    <div class="card">
        <h2><i class="fa-solid fa-chart-bar" style="color:#1976d2"></i> Security Summary (Last 24h)</h2>
        <table>
            <tr>
                <th>Top Attack Type</th>
                <td><?= htmlspecialchars($report['top_attack_type'] ?? 'None') ?></td>
            </tr>
            <tr>
                <th>Top Attacker IP</th>
                <td><?= htmlspecialchars($report['top_attacker_ip'] ?? 'None') ?></td>
            </tr>
            <tr>
                <th>Active Bans</th>
                <td><?= $report['active_bans'] ?? 0 ?></td>
            </tr>
            <tr>
                <th>Full Report</th>
                <td>
                    <a href="https://127.0.0.1:5000/api/report?hours=24" target="_blank"
                       style="color:#1976d2;text-decoration:none;">
                        <i class="fa-solid fa-external-link"></i> View Full Report
                    </a>
                </td>
            </tr>
        </table>
    </div>

</div>

</body>
</html>