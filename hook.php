<?php

/**
 * SecurityAudit - Plugin GLPI
 * Fichier: hook.php
 *
 * GLPI 11 :
 *   ✅ $DB->doQuery()      → autorisé pour CREATE TABLE / DROP TABLE
 *   ✅ $migration->addField/addKey/dropTable → pour alter + suppression
 *   ❌ $DB->query()        → INTERDIT
 *   ❌ $DB->queryOrDie()   → INTERDIT
 *   ❌ $migration->createTable() → n'existe pas dans GLPI 11
 */

/**
 * Installation du plugin
 */
function plugin_securityaudit_install() {
    global $DB;

    $migration = new Migration(PLUGIN_SECURITYAUDIT_VERSION);

    $charset   = DBConnection::getDefaultCharset();
    $collation = DBConnection::getDefaultCollation();
    $sign      = DBConnection::getDefaultPrimaryKeySignOption();

    // ------------------------------------------------------------------
    // Table : journal d'audit
    // ------------------------------------------------------------------
    if (!$DB->tableExists('glpi_plugin_securityaudit_logs')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_securityaudit_logs` (
            `id`          int {$sign} NOT NULL AUTO_INCREMENT,
            `date`        datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `users_id`    int {$sign} NOT NULL DEFAULT '0',
            `user_name`   varchar(255) NOT NULL DEFAULT '',
            `ip_address`  varchar(45) NOT NULL DEFAULT '',
            `itemtype`    varchar(100) NOT NULL DEFAULT '',
            `items_id`    int {$sign} NOT NULL DEFAULT '0',
            `action`      varchar(50) NOT NULL DEFAULT '',
            `field`       varchar(100) NOT NULL DEFAULT '',
            `old_value`   text,
            `new_value`   text,
            `severity`    tinyint NOT NULL DEFAULT '0',
            PRIMARY KEY (`id`),
            KEY `date` (`date`),
            KEY `users_id` (`users_id`),
            KEY `itemtype` (`itemtype`),
            KEY `severity` (`severity`)
        ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation} ROW_FORMAT=DYNAMIC");
    }

    // ------------------------------------------------------------------
    // Table : alertes de sécurité
    // ------------------------------------------------------------------
    if (!$DB->tableExists('glpi_plugin_securityaudit_alerts')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_securityaudit_alerts` (
            `id`          int {$sign} NOT NULL AUTO_INCREMENT,
            `date`        datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `users_id`    int {$sign} NOT NULL DEFAULT '0',
            `type`        varchar(50) NOT NULL DEFAULT '',
            `message`     text NOT NULL,
            `ip_address`  varchar(45) NOT NULL DEFAULT '',
            `is_read`     tinyint NOT NULL DEFAULT '0',
            `severity`    tinyint NOT NULL DEFAULT '1',
            PRIMARY KEY (`id`),
            KEY `date` (`date`),
            KEY `is_read` (`is_read`),
            KEY `type` (`type`)
        ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation} ROW_FORMAT=DYNAMIC");
    }

    // ------------------------------------------------------------------
    // Table : mots de passe faibles
    // ------------------------------------------------------------------
    if (!$DB->tableExists('glpi_plugin_securityaudit_passwords')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_securityaudit_passwords` (
            `id`             int {$sign} NOT NULL AUTO_INCREMENT,
            `users_id`       int {$sign} NOT NULL DEFAULT '0',
            `check_date`     datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `strength_score` tinyint NOT NULL DEFAULT '0',
            `issues`         text,
            `notified`       tinyint NOT NULL DEFAULT '0',
            PRIMARY KEY (`id`),
            UNIQUE KEY `users_id` (`users_id`),
            KEY `strength_score` (`strength_score`)
        ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation} ROW_FORMAT=DYNAMIC");
    }

    // ------------------------------------------------------------------
    // Table : configuration
    // ------------------------------------------------------------------
    if (!$DB->tableExists('glpi_plugin_securityaudit_configs')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_securityaudit_configs` (
            `id`    int {$sign} NOT NULL AUTO_INCREMENT,
            `name`  varchar(100) NOT NULL DEFAULT '',
            `value` text,
            PRIMARY KEY (`id`),
            UNIQUE KEY `name` (`name`)
        ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation} ROW_FORMAT=DYNAMIC");
    }

    $migration->executeMigration();

    // ------------------------------------------------------------------
    // Config par défaut
    // ------------------------------------------------------------------
    $defaults = [
        'log_retention_days'      => '90',
        'alert_on_bulk_delete'    => '1',
        'alert_on_login_fail'     => '1',
        'weak_password_min_score' => '60',
        'alert_email'             => '',
        'dashboard_items'         => '20',
    ];

    foreach ($defaults as $name => $value) {
        $exists = $DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_configs',
            'WHERE' => ['name' => $name],
        ]);
        if ($exists->count() === 0) {
            $DB->insert('glpi_plugin_securityaudit_configs', [
                'name'  => $name,
                'value' => $value,
            ]);
        }
    }

    // ------------------------------------------------------------------
    // Droits GLPI
    // ------------------------------------------------------------------
    // Ajout des droits — on ignore les doublons éventuels (réinstallation)
    $rights = [
        'plugin_securityaudit_log',
        'plugin_securityaudit_alert',
        'plugin_securityaudit_config',
    ];
    foreach ($rights as $right) {
        $existing = $DB->request([
            'COUNT' => 'id',
            'FROM'  => 'glpi_profilerights',
            'WHERE' => ['name' => $right],
        ]);
        if ($existing->current()['COUNT(id)'] === 0) {
            ProfileRight::addProfileRights([$right]);
        }
    }

    return true;
}

/**
 * Désinstallation
 */
function plugin_securityaudit_uninstall() {
    $migration = new Migration(PLUGIN_SECURITYAUDIT_VERSION);

    foreach ([
        'glpi_plugin_securityaudit_logs',
        'glpi_plugin_securityaudit_alerts',
        'glpi_plugin_securityaudit_passwords',
        'glpi_plugin_securityaudit_configs',
    ] as $table) {
        $migration->dropTable($table);
    }

    $migration->executeMigration();

    ProfileRight::deleteProfileRights([
        'plugin_securityaudit_log',
        'plugin_securityaudit_alert',
        'plugin_securityaudit_config',
    ]);

    return true;
}
