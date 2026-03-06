<?php

namespace GlpiPlugin\Securityaudit;

use CommonGLPI;
use Session;
use Plugin;

class Dashboard extends CommonGLPI
{
    public static $rightname = 'plugin_securityaudit_log';

    public static function getTypeName($nb = 0): string
    {
        return 'SecurityAudit';
    }

    public static function getMenuName(): string
    {
        return 'SecurityAudit';
    }

    public static function getMenuContent(): array
    {
        if (!Session::haveRight(self::$rightname, READ)) {
            return [];
        }

        $base = Plugin::getWebDir('securityaudit');

        return [
            'title' => 'SecurityAudit',
            'page'  => $base . '/front/dashboard.php',
            'icon'  => 'ti ti-shield-lock',
            'links' => [
                'Tableau de bord' => $base . '/front/dashboard.php',
                "Journal d'audit" => $base . '/front/log.php',
                'Alertes'         => $base . '/front/alert.php',
                'Mots de passe'   => $base . '/front/password.php',
                'Configuration'   => $base . '/front/config.form.php',
            ],
        ];
    }

    public static function getStats(): array
    {
        global $DB;

        $since24h = date('Y-m-d H:i:s', strtotime('-24 hours'));
        $since7d  = date('Y-m-d H:i:s', strtotime('-7 days'));
        $minScore = (int) Config::getConfig('weak_password_min_score', 60);

        // Logs 24h
        $logs24h = 0;
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_logs',
            'WHERE' => [['date' => ['>=', $since24h]]],
        ]) as $row) {
            $logs24h++;
        }

        // Alertes non lues
        $unreadAlerts = 0;
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_alerts',
            'WHERE' => ['is_read' => 0],
        ]) as $row) {
            $unreadAlerts++;
        }

        // Alertes critiques 7j
        $criticalAlerts = 0;
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_alerts',
            'WHERE' => ['severity' => 2, ['date' => ['>=', $since7d]]],
        ]) as $row) {
            $criticalAlerts++;
        }

        // Mots de passe faibles
        $weakPasswords = 0;
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_passwords',
            'WHERE' => ['strength_score' => ['<', $minScore]],
        ]) as $row) {
            $weakPasswords++;
        }

        // Utilisateurs actifs 24h
        $activeUserIds = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_logs',
            'WHERE' => [['date' => ['>=', $since24h]]],
        ]) as $row) {
            $activeUserIds[$row['users_id']] = true;
        }
        $activeUsers = count($activeUserIds);

        // Actions par type 24h
        $actionStats = [];
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_logs',
            'WHERE' => [['date' => ['>=', $since24h]]],
        ]) as $row) {
            $action = $row['action'];
            $actionStats[$action] = ($actionStats[$action] ?? 0) + 1;
        }
        arsort($actionStats);
        $actionStats = array_slice($actionStats, 0, 6, true);

        // Dernières alertes
        $lastAlerts = iterator_to_array($DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_alerts',
            'ORDER' => ['date DESC'],
            'LIMIT' => 5,
        ]));

        return [
            'logs_24h'        => $logs24h,
            'unread_alerts'   => $unreadAlerts,
            'critical_alerts' => $criticalAlerts,
            'weak_passwords'  => $weakPasswords,
            'active_users'    => $activeUsers,
            'action_stats'    => $actionStats,
            'last_alerts'     => $lastAlerts,
        ];
    }
}
