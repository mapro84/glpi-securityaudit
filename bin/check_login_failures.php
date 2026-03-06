<?php
/**
 * SecurityAudit - Détection connexions échouées
 * Auteur : Mario Prospero
 * Appelé par cron système toutes les 15 minutes
 */

// Depuis plugins/securityaudit/bin/ → remonter 3 niveaux = racine GLPI
$glpiRoot = dirname(__DIR__, 3);
chdir($glpiRoot);

require_once $glpiRoot . '/vendor/autoload.php';
require_once $glpiRoot . '/config/config_db.php';

// DB est la classe définie dans config_db.php qui étend DBmysql avec les credentials
$DB = new DB();
global $DB;

$since    = date('Y-m-d H:i:s', strtotime('-15 minutes'));
$alertSince = date('Y-m-d H:i:s', strtotime('-1 hour'));

// Récupérer les échecs de connexion des 15 dernières minutes
$failures = [];
foreach ($DB->request([
    'FROM'  => 'glpi_events',
    'WHERE' => [
        'service' => 'login',
        'level'   => 3,
        ['message' => ['LIKE', 'Connexion échouée de % depuis l\'IP %']],
        ['date'    => ['>=', $since]],
    ],
]) as $row) {
    // Extraire login et IP depuis le message
    // Format : "Connexion échouée de LOGIN depuis l'IP X.X.X.X"
    if (preg_match("/Connexion échouée de (.+) depuis l'IP (.+)$/", $row['message'], $matches)) {
        $login = trim($matches[1]);
        $ip    = trim($matches[2]);
        $key   = $login . '|' . $ip;
        $failures[$key] = ($failures[$key] ?? 0) + 1;
    }
}

// Déclencher une alerte si >= 3 échecs pour le même login/IP
foreach ($failures as $key => $count) {
    if ($count < 3) continue;

    [$login, $ip] = explode('|', $key);

    // Vérifier qu'on n'a pas déjà alerté dans la dernière heure
    $alreadyAlerted = false;
    foreach ($DB->request([
        'FROM'  => 'glpi_plugin_securityaudit_alerts',
        'WHERE' => [
            'type'    => 'login_failure',
            ['message' => ['LIKE', "%{$login}%"]],
            ['date'   => ['>=', $alertSince]],
        ],
    ]) as $a) {
        $alreadyAlerted = true;
        break;
    }

    if (!$alreadyAlerted) {
        $DB->insert('glpi_plugin_securityaudit_alerts', [
            'date'       => date('Y-m-d H:i:s'),
            'users_id'   => 0,
            'type'       => 'login_failure',
            'message'    => sprintf(
                '%d tentatives de connexion échouées en 15 min pour "%s" depuis l\'IP %s',
                $count,
                $login,
                $ip
            ),
            'ip_address' => $ip,
            'is_read'    => 0,
            'severity'   => 1,
        ]);
        echo date('Y-m-d H:i:s') . " Alerte créée : {$count} échecs pour {$login} depuis {$ip}\n";
    }
}

echo date('Y-m-d H:i:s') . " Vérification terminée.\n";
