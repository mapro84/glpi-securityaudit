<?php

include('../../../inc/includes.php');

Session::checkRight('plugin_securityaudit_config', UPDATE);

// GLPI gère le CSRF automatiquement via csrf_compliant dans setup.php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'save_config') {
    foreach (['log_retention_days', 'weak_password_min_score', 'alert_email', 'dashboard_items'] as $field) {
        if (isset($_POST[$field])) {
            GlpiPlugin\Securityaudit\Config::setConfig($field, $_POST[$field]);
        }
    }
    GlpiPlugin\Securityaudit\Config::setConfig('alert_on_bulk_delete', isset($_POST['alert_on_bulk_delete']) ? '1' : '0');
    GlpiPlugin\Securityaudit\Config::setConfig('alert_on_login_fail',  isset($_POST['alert_on_login_fail'])  ? '1' : '0');

    Session::addMessageAfterRedirect('✅ Configuration sauvegardée avec succès.', false, INFO);
    Html::back();
}

Html::header('SecurityAudit - Configuration', $_SERVER['PHP_SELF'], 'tools', 'securityaudit');

$config = new GlpiPlugin\Securityaudit\Config();
$config->showForm();

Html::footer();
