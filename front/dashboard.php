<?php

/**
 * SecurityAudit - Tableau de bord principal
 */

include('../../../inc/includes.php');

Session::checkRight('plugin_securityaudit_log', READ);

Html::header('SecurityAudit - Tableau de bord', $_SERVER['PHP_SELF'], 'tools', 'securityaudit');

$stats = GlpiPlugin\Securityaudit\Dashboard::getStats();

?>
<div class="container-fluid px-4">

    <!-- Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h1 class="h3"><i class="ti ti-shield-lock me-2"></i>SecurityAudit - Tableau de bord</h1>
        <span class="text-muted small">Dernière mise à jour : <?= date('d/m/Y H:i') ?></span>
    </div>

    <!-- KPI Cards -->
    <div class="row g-3 mb-4">
        <div class="col-md-3">
            <div class="card border-primary h-100">
                <div class="card-body text-center">
                    <i class="ti ti-list fs-1 text-primary"></i>
                    <div class="display-6 fw-bold text-primary"><?= number_format($stats['logs_24h']) ?></div>
                    <div class="text-muted">Actions loguées (24h)</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-warning h-100">
                <div class="card-body text-center">
                    <i class="ti ti-bell-ringing fs-1 text-warning"></i>
                    <div class="display-6 fw-bold text-warning"><?= $stats['unread_alerts'] ?></div>
                    <div class="text-muted">Alertes non lues</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-danger h-100">
                <div class="card-body text-center">
                    <i class="ti ti-alert-triangle fs-1 text-danger"></i>
                    <div class="display-6 fw-bold text-danger"><?= $stats['critical_alerts'] ?></div>
                    <div class="text-muted">Alertes critiques (7j)</div>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card border-danger h-100">
                <div class="card-body text-center">
                    <i class="ti ti-key fs-1 text-danger"></i>
                    <div class="display-6 fw-bold text-danger"><?= $stats['weak_passwords'] ?></div>
                    <div class="text-muted">Mots de passe faibles</div>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-3">
        <!-- Activité par action -->
        <div class="col-md-5">
            <div class="card h-100">
                <div class="card-header"><i class="ti ti-chart-bar me-1"></i>Activité par type (24h)</div>
                <div class="card-body">
                    <?php if (empty($stats['action_stats'])): ?>
                        <p class="text-muted text-center py-4">Aucune activité dans les dernières 24h</p>
                    <?php else: ?>
                        <?php
                        $total = array_sum($stats['action_stats']);
                        $colors = ['add' => 'success', 'update' => 'primary', 'delete' => 'danger', 'purge' => 'dark', 'login' => 'info', 'logout' => 'secondary'];
                        foreach ($stats['action_stats'] as $action => $count):
                            $pct   = $total > 0 ? round($count / $total * 100) : 0;
                            $color = $colors[$action] ?? 'secondary';
                        ?>
                        <div class="mb-2">
                            <div class="d-flex justify-content-between mb-1">
                                <span class="badge bg-<?= $color ?>"><?= htmlspecialchars($action) ?></span>
                                <span><?= $count ?> (<?= $pct ?>%)</span>
                            </div>
                            <div class="progress" style="height:8px">
                                <div class="progress-bar bg-<?= $color ?>" style="width:<?= $pct ?>%"></div>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Dernières alertes -->
        <div class="col-md-7">
            <div class="card h-100">
                <div class="card-header d-flex justify-content-between">
                    <span><i class="ti ti-bell me-1"></i>Dernières alertes</span>
                    <a href="alert.php" class="btn btn-sm btn-outline-secondary">Voir tout</a>
                </div>
                <div class="card-body p-0">
                    <table class="table table-sm mb-0">
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>Type</th>
                                <th>Sévérité</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php if (empty($stats['last_alerts'])): ?>
                            <tr><td colspan="4" class="text-center text-muted py-4">Aucune alerte 🎉</td></tr>
                        <?php else: ?>
                            <?php
                            $severityLabels = ['info', 'warning', 'danger'];
                            $severityIcons  = ['ti-info-circle', 'ti-alert-circle', 'ti-alert-triangle'];
                            foreach ($stats['last_alerts'] as $alert):
                                $sev = (int)$alert['severity'];
                            ?>
                            <tr class="<?= !$alert['is_read'] ? 'table-active fw-bold' : '' ?>">
                                <td class="text-nowrap small"><?= date('d/m H:i', strtotime($alert['date'])) ?></td>
                                <td><code class="small"><?= htmlspecialchars($alert['type']) ?></code></td>
                                <td><span class="badge bg-<?= $severityLabels[$sev] ?>"><i class="ti <?= $severityIcons[$sev] ?>"></i></span></td>
                                <td class="small"><?= htmlspecialchars(mb_substr($alert['message'], 0, 60)) ?>...</td>
                            </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <!-- Liens rapides -->
    <div class="row g-3 mt-2">
        <div class="col-12">
            <div class="card">
                <div class="card-body d-flex gap-2">
                    <a href="log.php" class="btn btn-outline-primary"><i class="ti ti-list me-1"></i>Journal d'audit</a>
                    <a href="alert.php" class="btn btn-outline-warning"><i class="ti ti-bell me-1"></i>Alertes</a>
                    <a href="password.php" class="btn btn-outline-danger"><i class="ti ti-key me-1"></i>Mots de passe faibles</a>
                    <a href="config.form.php" class="btn btn-outline-secondary"><i class="ti ti-settings me-1"></i>Configuration</a>
                </div>
            </div>
        </div>
    </div>

</div>

<?php Html::footer(); ?>
