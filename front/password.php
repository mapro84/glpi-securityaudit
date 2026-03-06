<?php

/**
 * SecurityAudit - Mots de passe faibles
 */

include('../../../inc/includes.php');

Session::checkRight('plugin_securityaudit_log', READ);

Html::header('SecurityAudit - Mots de passe faibles', $_SERVER['PHP_SELF'], 'tools', 'securityaudit');

global $DB;

$minScore = (int) GlpiPlugin\Securityaudit\Config::getConfig('weak_password_min_score', 60);
$weak     = GlpiPlugin\Securityaudit\PasswordChecker::getWeakPasswordUsers($minScore);

// Enrichir avec le nom d'utilisateur
$userIds = array_column($weak, 'users_id');
$users   = [];
if (!empty($userIds)) {
    foreach ($DB->request(['SELECT' => ['id', 'name', 'realname', 'firstname', 'last_login'], 'FROM' => 'glpi_users', 'WHERE' => ['id' => $userIds]]) as $u) {
        $users[$u['id']] = $u;
    }
}

?>
<div class="container-fluid px-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h3"><i class="ti ti-key me-2"></i>Mots de passe faibles</h1>
        <span class="badge bg-danger fs-6"><?= count($weak) ?> utilisateur(s) concerné(s)</span>
    </div>

    <!-- Info seuil -->
    <div class="alert alert-info mb-3">
        <i class="ti ti-info-circle me-1"></i>
        Seuil configuré : score minimum <strong><?= $minScore ?>/100</strong>.
        <a href="config.form.php" class="alert-link">Modifier la configuration</a>
    </div>

    <?php if (empty($weak)): ?>
    <div class="card">
        <div class="card-body text-center py-5">
            <i class="ti ti-shield-check fs-1 text-success"></i>
            <h4 class="mt-2 text-success">Aucun mot de passe faible détecté ! 🎉</h4>
            <p class="text-muted">Tous les mots de passe analysés ont un score ≥ <?= $minScore ?>/100</p>
        </div>
    </div>
    <?php else: ?>
    <div class="card">
        <div class="card-body p-0">
            <table class="table table-hover mb-0">
                <thead class="table-dark">
                    <tr>
                        <th>Utilisateur</th>
                        <th>Nom complet</th>
                        <th>Score</th>
                        <th>Niveau</th>
                        <th>Problèmes détectés</th>
                        <th>Dernière vérif.</th>
                        <th>Dernière connexion</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($weak as $row):
                    $user   = $users[$row['users_id']] ?? [];
                    $issues = json_decode($row['issues'] ?? '[]', true) ?: [];
                    $score  = (int)$row['strength_score'];
                    $level  = GlpiPlugin\Securityaudit\PasswordChecker::level($score);
                    $scoreClass = $score < 30 ? 'danger' : ($score < 60 ? 'warning' : 'info');
                ?>
                <tr>
                    <td><strong><?= htmlspecialchars($user['name'] ?? "user#{$row['users_id']}") ?></strong></td>
                    <td><?= htmlspecialchars(trim(($user['firstname'] ?? '') . ' ' . ($user['realname'] ?? ''))) ?></td>
                    <td>
                        <div class="d-flex align-items-center gap-2">
                            <div class="progress flex-grow-1" style="height:8px">
                                <div class="progress-bar bg-<?= $scoreClass ?>" style="width:<?= $score ?>%"></div>
                            </div>
                            <span class="fw-bold text-<?= $scoreClass ?>"><?= $score ?>/100</span>
                        </div>
                    </td>
                    <td><span class="badge bg-<?= $scoreClass ?>"><?= htmlspecialchars($level) ?></span></td>
                    <td>
                        <?php if (!empty($issues)): ?>
                        <ul class="list-unstyled mb-0 small">
                            <?php foreach ($issues as $issue): ?>
                            <li><i class="ti ti-x text-danger me-1"></i><?= htmlspecialchars($issue) ?></li>
                            <?php endforeach; ?>
                        </ul>
                        <?php else: ?>
                        <span class="text-muted">—</span>
                        <?php endif; ?>
                    </td>
                    <td class="small text-muted"><?= date('d/m/Y', strtotime($row['check_date'])) ?></td>
                    <td class="small text-muted">
                        <?= !empty($user['last_login']) ? date('d/m/Y', strtotime($user['last_login'])) : '—' ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php endif; ?>
</div>

<?php Html::footer(); ?>
