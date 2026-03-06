<?php

/**
 * SecurityAudit - Journal d'audit
 */

include('../../../inc/includes.php');

Session::checkRight('plugin_securityaudit_log', READ);

Html::header('SecurityAudit - Journal d\'audit', $_SERVER['PHP_SELF'], 'tools', 'securityaudit');

global $DB;

// Filtres
$filters = [
    'action'   => $_GET['action']   ?? '',
    'itemtype' => $_GET['itemtype'] ?? '',
    'severity' => $_GET['severity'] ?? '',
    'search'   => $_GET['search']   ?? '',
    'since'    => $_GET['since']    ?? '7',
];

$where = [];
if ($filters['action'])   $where['action']   = $filters['action'];
if ($filters['itemtype']) $where['itemtype'] = $filters['itemtype'];
if ($filters['severity'] !== '') $where['severity'] = (int)$filters['severity'];
$since = date('Y-m-d H:i:s', strtotime('-' . (int)$filters['since'] . ' days'));
$where[] = ['date' => ['>=', $since]];

$page  = max(1, (int)($_GET['page'] ?? 1));
$limit = 50;

$total = $DB->request(['COUNT' => 'id', 'FROM' => 'glpi_plugin_securityaudit_logs', 'WHERE' => $where])->current()['COUNT(id)'] ?? 0;
$logs  = $DB->request(['FROM' => 'glpi_plugin_securityaudit_logs', 'WHERE' => $where, 'ORDER' => ['date DESC'], 'LIMIT' => $limit, 'START' => ($page - 1) * $limit]);

$severityBadge = ['<span class="badge bg-info">Info</span>', '<span class="badge bg-warning">Warning</span>', '<span class="badge bg-danger">Critique</span>'];

?>
<div class="container-fluid px-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h3"><i class="ti ti-list me-2"></i>Journal d'audit</h1>
        <span class="badge bg-secondary"><?= number_format($total) ?> entrées</span>
    </div>

    <!-- Filtres -->
    <div class="card mb-3">
        <div class="card-body">
            <form method="get" class="row g-2 align-items-end">
                <div class="col-md-2">
                    <label class="form-label small">Période</label>
                    <select name="since" class="form-select form-select-sm">
                        <?php foreach (['1' => '24h', '7' => '7 jours', '30' => '30 jours', '90' => '90 jours'] as $v => $l): ?>
                        <option value="<?= $v ?>" <?= $filters['since'] == $v ? 'selected' : '' ?>><?= $l ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-2">
                    <label class="form-label small">Action</label>
                    <select name="action" class="form-select form-select-sm">
                        <option value="">Toutes</option>
                        <?php foreach (['add', 'update', 'delete', 'purge', 'login', 'logout'] as $a): ?>
                        <option value="<?= $a ?>" <?= $filters['action'] === $a ? 'selected' : '' ?>><?= ucfirst($a) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-2">
                    <label class="form-label small">Sévérité</label>
                    <select name="severity" class="form-select form-select-sm">
                        <option value="">Toutes</option>
                        <option value="0" <?= $filters['severity'] === '0' ? 'selected' : '' ?>>Info</option>
                        <option value="1" <?= $filters['severity'] === '1' ? 'selected' : '' ?>>Warning</option>
                        <option value="2" <?= $filters['severity'] === '2' ? 'selected' : '' ?>>Critique</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <label class="form-label small">Recherche</label>
                    <input type="text" name="search" class="form-control form-control-sm" value="<?= htmlspecialchars($filters['search']) ?>" placeholder="Utilisateur, IP...">
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-primary btn-sm w-100">🔍 Filtrer</button>
                </div>
                <div class="col-md-1">
                    <a href="log.php" class="btn btn-outline-secondary btn-sm w-100">↺</a>
                </div>
            </form>
        </div>
    </div>

    <!-- Table -->
    <div class="card">
        <div class="card-body p-0">
            <table class="table table-hover table-sm mb-0">
                <thead class="table-dark">
                    <tr>
                        <th>Date</th>
                        <th>Utilisateur</th>
                        <th>IP</th>
                        <th>Action</th>
                        <th>Objet</th>
                        <th>Champ</th>
                        <th>Ancien</th>
                        <th>Nouveau</th>
                        <th>Sévérité</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($logs as $row): ?>
                    <tr class="<?= (int)$row['severity'] === 2 ? 'table-danger' : ((int)$row['severity'] === 1 ? 'table-warning' : '') ?>">
                        <td class="text-nowrap small"><?= date('d/m/Y H:i:s', strtotime($row['date'])) ?></td>
                        <td class="small"><?= htmlspecialchars($row['user_name']) ?></td>
                        <td class="small text-muted"><?= htmlspecialchars($row['ip_address']) ?></td>
                        <td><span class="badge bg-secondary"><?= htmlspecialchars($row['action']) ?></span></td>
                        <td class="small"><?= htmlspecialchars($row['itemtype']) ?>#<?= $row['items_id'] ?></td>
                        <td class="small text-muted"><?= htmlspecialchars($row['field']) ?></td>
                        <td class="small"><?= htmlspecialchars(mb_substr((string)$row['old_value'], 0, 30)) ?></td>
                        <td class="small"><?= htmlspecialchars(mb_substr((string)$row['new_value'], 0, 30)) ?></td>
                        <td><?= $severityBadge[(int)$row['severity']] ?? '' ?></td>
                    </tr>
                <?php endforeach; ?>
                <?php if ($total === 0): ?>
                    <tr><td colspan="9" class="text-center text-muted py-4">Aucun log trouvé</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php if ($total > $limit): ?>
        <div class="card-footer">
            <nav>
                <ul class="pagination pagination-sm mb-0">
                    <?php for ($p = 1; $p <= ceil($total / $limit); $p++): ?>
                    <li class="page-item <?= $p === $page ? 'active' : '' ?>">
                        <a class="page-link" href="?<?= http_build_query(array_merge($filters, ['page' => $p])) ?>"><?= $p ?></a>
                    </li>
                    <?php endfor; ?>
                </ul>
            </nav>
        </div>
        <?php endif; ?>
    </div>
</div>

<?php Html::footer(); ?>
