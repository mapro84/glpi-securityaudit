<?php

namespace GlpiPlugin\Securityaudit;

/**
 * Capture tous les événements GLPI et génère logs + alertes
 * Détection connexions échouées : trigger MariaDB (temps réel)
 * Auteur : Mario Prospero
 */
class HookHandler
{
    /**
     * Déclenché AVANT le hash — mot de passe en clair disponible
     */
    public static function preItemAdd(\CommonDBTM $item): void
    {
        if (!($item instanceof \User)) {
            return;
        }
        $password = $item->input['password'] ?? null;
        if ($password && !self::isHashed($password)) {
            $_SESSION['securityaudit_pending_password'] = $password;
        }
    }

    /**
     * Déclenché AVANT le hash lors d'une modification
     */
    public static function preItemUpdate(\CommonDBTM $item): void
    {
        if (!($item instanceof \User)) {
            return;
        }
        $password = $item->input['password'] ?? null;
        if ($password && !self::isHashed($password)) {
            PasswordChecker::checkAndStore($item->getID(), $password);
        }
    }

    /**
     * Après création — on récupère l'ID et on score le MDP stocké en session
     */
    public static function itemAdded(\CommonDBTM $item): void
    {
        if ($item instanceof \User) {
            $password = $_SESSION['securityaudit_pending_password'] ?? null;
            if ($password) {
                PasswordChecker::checkAndStore($item->getID(), $password);
                unset($_SESSION['securityaudit_pending_password']);
            }
        }
        self::log($item, 'add');
    }

    public static function itemUpdated(\CommonDBTM $item): void
    {
        self::log($item, 'update', $item->updates ?? []);
    }

    public static function itemDeleted(\CommonDBTM $item): void
    {
        self::log($item, 'delete');
        self::detectBulkDelete();
    }

    public static function itemPurged(\CommonDBTM $item): void
    {
        self::log($item, 'purge');
    }

    public static function userLogin(): void
    {
        $userId   = \Session::getLoginUserID() ?: 0;
        $userName = $_SESSION['glpiname'] ?? 'unknown';

        self::writeLog([
            'users_id'   => (int) $userId,
            'user_name'  => $userName,
            'ip_address' => self::getClientIp(),
            'itemtype'   => 'User',
            'items_id'   => (int) $userId,
            'action'     => 'login',
            'severity'   => 0,
        ]);
    }

    public static function userLogout(): void
    {
        $userId   = \Session::getLoginUserID() ?: 0;
        $userName = $_SESSION['glpiname'] ?? 'unknown';

        self::writeLog([
            'users_id'   => (int) $userId,
            'user_name'  => $userName,
            'ip_address' => self::getClientIp(),
            'itemtype'   => 'User',
            'items_id'   => (int) $userId,
            'action'     => 'logout',
            'severity'   => 0,
        ]);
    }

    // ---------------------------------------------------------------
    // Méthodes internes
    // ---------------------------------------------------------------

    private static function log(\CommonDBTM $item, string $action, array $updates = []): void
    {
        $shortType = (new \ReflectionClass($item))->getShortName();
        $userId    = \Session::getLoginUserID() ?: 0;
        $userName  = $_SESSION['glpiname'] ?? 'system';
        $ip        = self::getClientIp();
        $fields    = empty($updates) ? ['*'] : $updates;

        foreach ($fields as $field) {
            $oldVal = $item->oldvalues[$field] ?? null;
            $newVal = $item->fields[$field]    ?? null;

            if (strtolower((string) $field) === 'password') {
                $oldVal = $oldVal ? '***' : null;
                $newVal = $newVal ? '***' : null;
            }

            $severity = self::getSeverity($shortType, $action, (string) $field);

            self::writeLog([
                'users_id'   => (int) $userId,
                'user_name'  => $userName,
                'ip_address' => $ip,
                'itemtype'   => $shortType,
                'items_id'   => (int) $item->getID(),
                'action'     => $action,
                'field'      => (string) $field,
                'old_value'  => $oldVal !== null ? (string) $oldVal : null,
                'new_value'  => $newVal !== null ? (string) $newVal : null,
                'severity'   => $severity,
            ]);

            if ($severity >= 2) {
                self::createAlert(
                    $action . '_critical',
                    'critical',
                    "Action critique : {$action} sur {$shortType}#{$item->getID()} champ={$field} par {$userName}",
                    (int) $userId,
                    $ip
                );
            }
        }
    }

    public static function writeLog(array $data): void
    {
        global $DB;
        $DB->insert('glpi_plugin_securityaudit_logs', array_merge([
            'date'      => date('Y-m-d H:i:s'),
            'field'     => '',
            'old_value' => null,
            'new_value' => null,
            'severity'  => 0,
        ], $data));
    }

    public static function createAlert(string $type, string $level, string $message, int $userId = 0, string $ip = ''): void
    {
        global $DB;
        $severity = match ($level) {
            'critical' => 2,
            'warning'  => 1,
            default    => 0,
        };
        $DB->insert('glpi_plugin_securityaudit_alerts', [
            'date'       => date('Y-m-d H:i:s'),
            'users_id'   => $userId,
            'type'       => $type,
            'message'    => $message,
            'ip_address' => $ip ?: self::getClientIp(),
            'is_read'    => 0,
            'severity'   => $severity,
        ]);
    }

    private static function detectBulkDelete(): void
    {
        global $DB;
        $userId = \Session::getLoginUserID() ?: 0;
        $since  = date('Y-m-d H:i:s', strtotime('-5 minutes'));

        $count = 0;
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_logs',
            'WHERE' => [
                'users_id' => (int) $userId,
                'action'   => ['delete', 'purge'],
                ['date'    => ['>=', $since]],
            ],
        ]) as $row) {
            $count++;
        }

        $userName = $_SESSION['glpiname'] ?? 'unknown';
        if ($count >= 10) {
            self::createAlert(
                'bulk_delete',
                'critical',
                "Suppression massive : {$count} suppressions en 5 min par {$userName}",
                (int) $userId
            );
        }
    }

    private static function getSeverity(string $type, string $action, string $field): int
    {
        if (in_array($type, ['User', 'Profile', 'Entity', 'AuthLDAP'], true)) {
            if (in_array($action, ['delete', 'purge'], true)) return 2;
            if (in_array($field, ['is_active', 'profiles_id', 'is_superadmin'], true)) return 2;
        }
        if (in_array($action, ['delete', 'purge'], true)) return 1;
        if ($field === 'password') return 1;
        return 0;
    }

    private static function isHashed(string $password): bool
    {
        return strlen($password) >= 60 && str_starts_with($password, '$2');
    }

    public static function getClientIp(): string
    {
        foreach (['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
            if (!empty($_SERVER[$key])) {
                return trim(explode(',', $_SERVER[$key])[0]);
            }
        }
        return 'cli';
    }
}
