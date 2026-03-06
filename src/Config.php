<?php

namespace GlpiPlugin\Securityaudit;

use CommonGLPI;
use Session;
use Html;
use Plugin;

class Config extends CommonGLPI
{
    public static $rightname = 'plugin_securityaudit_config';

    public static function getTypeName($nb = 0): string
    {
        return 'SecurityAudit - Configuration';
    }

    public static function getConfig(string $name, mixed $default = null): mixed
    {
        global $DB;

        $result = $DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_configs',
            'WHERE' => ['name' => $name],
        ]);

        return $result->count() > 0 ? $result->current()['value'] : $default;
    }

    public static function setConfig(string $name, mixed $value): void
    {
        global $DB;

        $exists = $DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_configs',
            'WHERE' => ['name' => $name],
        ]);

        if ($exists->count() > 0) {
            $DB->update('glpi_plugin_securityaudit_configs', ['value' => $value], ['name' => $name]);
        } else {
            $DB->insert('glpi_plugin_securityaudit_configs', ['name' => $name, 'value' => $value]);
        }
    }

    public function showForm(int $id = 0): void
    {
        Session::checkRight(self::$rightname, UPDATE);

        $cfg = [
            'log_retention_days'      => self::getConfig('log_retention_days', 90),
            'alert_on_bulk_delete'    => self::getConfig('alert_on_bulk_delete', 1),
            'alert_on_login_fail'     => self::getConfig('alert_on_login_fail', 1),
            'weak_password_min_score' => self::getConfig('weak_password_min_score', 60),
            'alert_email'             => self::getConfig('alert_email', ''),
            'dashboard_items'         => self::getConfig('dashboard_items', 20),
        ];

        $formUrl    = Plugin::getWebDir('securityaudit') . '/front/config.form.php';
        $csrfToken  = $_SESSION['glpicsrftokens'][0] ?? Session::getNewCSRFToken();

        echo '<div class="card mt-3">';
        echo '<div class="card-header"><h3>⚙️ Configuration SecurityAudit</h3></div>';
        echo '<div class="card-body">';
        echo '<form method="post" action="' . htmlspecialchars($formUrl) . '">';
        echo '<input type="hidden" name="_glpi_csrf_token" value="' . htmlspecialchars($csrfToken) . '">';
        echo '<input type="hidden" name="action" value="save_config">';
        echo '<table class="table table-striped">';

        $fields = [
            ['log_retention_days',      'number', 'Rétention des logs (jours)',       7,  3650],
            ['weak_password_min_score', 'number', 'Score minimum mot de passe (0-100)', 0, 100],
            ['dashboard_items',         'number', 'Éléments par page (dashboard)',     5,  200],
        ];

        foreach ($fields as [$name, $type, $label, $min, $max]) {
            echo "<tr><td><label>{$label}</label></td>";
            echo "<td><input type='{$type}' name='{$name}' value='" . (int)$cfg[$name] . "' min='{$min}' max='{$max}' class='form-control'></td></tr>";
        }

        echo '<tr><td><label>Email alertes critiques</label></td>';
        echo '<td><input type="email" name="alert_email" value="' . htmlspecialchars((string)$cfg['alert_email']) . '" class="form-control" placeholder="admin@exemple.com"></td></tr>';

        echo '<tr><td><label>Alerte suppression massive</label></td>';
        echo '<td><input type="checkbox" name="alert_on_bulk_delete" value="1" ' . ($cfg['alert_on_bulk_delete'] ? 'checked' : '') . '></td></tr>';

        echo '<tr><td><label>Alerte connexions échouées</label></td>';
        echo '<td><input type="checkbox" name="alert_on_login_fail" value="1" ' . ($cfg['alert_on_login_fail'] ? 'checked' : '') . '></td></tr>';

        echo '</table>';
        echo '<button type="submit" class="btn btn-primary mt-2">💾 Sauvegarder</button>';
        echo '</form></div></div>';
    }
}
