<?php

/**
 * SecurityAudit - Alertes de sécurité
 */

include('../../../inc/includes.php');

Session::checkRight('plugin_securityaudit_alert', READ);

// Action : marquer comme lu
if (isset($_POST['mark_read']) && Session::validateCSRF($_POST)) {
    global $DB;
    $ids = array_map('intval', (array)$_POST['ids']);
    if (!empty($ids)) {
        $DB->update('glpi_plugin_securityaudit_alerts', ['is_read' => 1], ['id' => $ids]);
    }
    Html::back();
}

Html::header('SecurityAudit - Alertes', $_SERVER['PHP_SELF'], 'tools', 'securityaudit');

global $DB;

$where = [];
if (isset($_GET['unread_only']) && $_GET['unread_only']) {
    $where['is_read'] = 0;
}
if (isset($_GET['severity']) && $_GET['severity'] !== '') {
    $where['severity'] = (int)$_GET['severity'];
}

$alerts = $DB->request(['FROM' => 'glpi_plugin_securityaudit_alerts', 'WHERE' => $where, 'ORDER' => ['date DESC'], 'LIMIT' => 100]);
$total  = $DB->request(['COUNT' => 'id', 'FROM' => 'glpi_plugin_securityaudit_alerts', 'WHERE' => ['is_read' => 0]])->current()['COUNT(id)'] ?? 0;

$severityConfig = [
    0 => ['label' => 'Info',     'class' => 'info',    'icon' => 'ti-info-circle'],
    1 => ['label' => 'Warning',  'class' => 'warning', 'icon' => 'ti-alert-circle'],
    2 => ['label' => 'Critique', 'class' => 'danger',  'icon' => 'ti-alert-triangle'],
];

?>
<div class="container-fluid px-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h3"><i class="ti ti-bell me-2"></i>Alertes de sécurité
            <?php if ($total > 0): ?>
            <span class="badge bg-danger ms-2"><?= $total ?> non lues</span>
            <?php endif; ?>
        </h1>
    </div>

    <!-- Filtres rapides -->
    <div class="d-flex gap-2 mb-3">
        <a href="alert.php" class="btn btn-sm btn-outline-secondary">Toutes</a>
        <a href="alert.php?unread_only=1" class="btn btn-sm btn-outline-warning">Non lues</a>
        <a href="alert.php?severity=2" class="btn btn-sm btn-outline-danger">Critiques</a>
        <a href="alert.php?severity=1" class="btn btn-sm btn-outline-warning">Warnings</a>
    </div>

    <form method="post">
        <?= Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]) ?>
        <?= Html::hidden('mark_read', ['value' => '1']) ?>

        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span>Alertes</span>
                <button type="submit" class="btn btn-sm btn-outline-success">✓ Marquer sélection comme lu</button>
            </div>
            <div class="card-body p-0">
                <table class="table table-hover mb-0">
                    <thead class="table-dark">
                        <tr>
                            <th width="30"><input type="checkbox" id="checkAll"></th>
                            <th>Date</th>
                            <th>Type</th>
                            <th>Sévérité</th>
                            <th>Message</th>
                            <th>IP</th>
                            <th>Statut</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($alerts as $alert):
                        $sev = (int)$alert['severity'];
                        $sc  = $severityConfig[$sev] ?? $severityConfig[0];
                    ?>
                        <tr class="<?= !$alert['is_read'] ? 'fw-bold' : 'opacity-75' ?>">
                            <td><input type="checkbox" name="ids[]" value="<?= $alert['id'] ?>"></td>
                            <td class="text-nowrap"><?= date('d/m/Y H:i', strtotime($alert['date'])) ?></td>
                            <td><code class="small"><?= htmlspecialchars($alert['type']) ?></code></td>
                            <td><span class="badge bg-<?= $sc['class'] ?>"><i class="ti <?= $sc['icon'] ?> me-1"></i><?= $sc['label'] ?></span></td>
                            <td><?= htmlspecialchars($alert['message']) ?></td>
                            <td class="text-muted small"><?= htmlspecialchars($alert['ip_address']) ?></td>
                            <td><?= $alert['is_read'] ? '<span class="text-muted">Lu</span>' : '<span class="badge bg-primary">Nouveau</span>' ?></td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if (iterator_count($alerts) === 0): ?>
                        <tr><td colspan="7" class="text-center text-muted py-4">🎉 Aucune alerte</td></tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </form>
</div>

<script>
document.getElementById('checkAll').addEventListener('change', function() {
    document.querySelectorAll('input[name="ids[]"]').forEach(cb => cb.checked = this.checked);
});
</script>

<?php Html::footer(); ?>
