<?php

/**
 * SecurityAudit - Plugin GLPI 11
 * Auteur : Mario Prospero
 *
 * setup.php — RÈGLES STRICTES GLPI 11 :
 *   ❌ Pas de 'use' au niveau global
 *   ❌ Pas d'instanciation de classe au niveau global
 *   ✅ Uniquement les fonctions plugin_*
 */

define('PLUGIN_SECURITYAUDIT_VERSION', '1.0.0');
define('PLUGIN_SECURITYAUDIT_MIN_GLPI', '11.0.0');
define('PLUGIN_SECURITYAUDIT_MAX_GLPI', '12.0.0');

function plugin_init_securityaudit() {
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant']['securityaudit'] = true;
    $PLUGIN_HOOKS['config_page']['securityaudit'] = 'front/config.form.php';

    // Autoloader PSR-4
    spl_autoload_register(function ($class) {
        $prefix = 'GlpiPlugin\\Securityaudit\\';
        if (strpos($class, $prefix) === 0) {
            $relative = substr($class, strlen($prefix));
            $file = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }
    });

    // pre_item_add/update → mot de passe EN CLAIR disponible ici
    $PLUGIN_HOOKS['pre_item_add']['securityaudit']    = ['User' => ['GlpiPlugin\Securityaudit\HookHandler', 'preItemAdd']];
    $PLUGIN_HOOKS['pre_item_update']['securityaudit'] = ['User' => ['GlpiPlugin\Securityaudit\HookHandler', 'preItemUpdate']];

    // Hooks CRUD — syntaxe GLPI 11 : tableau par itemtype
    $PLUGIN_HOOKS['item_add']['securityaudit'] = [
        'User'             => ['GlpiPlugin\Securityaudit\HookHandler', 'itemAdded'],
        'Computer'         => ['GlpiPlugin\Securityaudit\HookHandler', 'itemAdded'],
        'NetworkEquipment' => ['GlpiPlugin\Securityaudit\HookHandler', 'itemAdded'],
        'Software'         => ['GlpiPlugin\Securityaudit\HookHandler', 'itemAdded'],
        'Ticket'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemAdded'],
        'Problem'          => ['GlpiPlugin\Securityaudit\HookHandler', 'itemAdded'],
        'Change'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemAdded'],
        'Profile'          => ['GlpiPlugin\Securityaudit\HookHandler', 'itemAdded'],
        'Entity'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemAdded'],
    ];

    $PLUGIN_HOOKS['item_update']['securityaudit'] = [
        'User'             => ['GlpiPlugin\Securityaudit\HookHandler', 'itemUpdated'],
        'Computer'         => ['GlpiPlugin\Securityaudit\HookHandler', 'itemUpdated'],
        'NetworkEquipment' => ['GlpiPlugin\Securityaudit\HookHandler', 'itemUpdated'],
        'Software'         => ['GlpiPlugin\Securityaudit\HookHandler', 'itemUpdated'],
        'Ticket'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemUpdated'],
        'Problem'          => ['GlpiPlugin\Securityaudit\HookHandler', 'itemUpdated'],
        'Change'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemUpdated'],
        'Profile'          => ['GlpiPlugin\Securityaudit\HookHandler', 'itemUpdated'],
        'Entity'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemUpdated'],
    ];

    $PLUGIN_HOOKS['item_delete']['securityaudit'] = [
        'User'             => ['GlpiPlugin\Securityaudit\HookHandler', 'itemDeleted'],
        'Computer'         => ['GlpiPlugin\Securityaudit\HookHandler', 'itemDeleted'],
        'NetworkEquipment' => ['GlpiPlugin\Securityaudit\HookHandler', 'itemDeleted'],
        'Software'         => ['GlpiPlugin\Securityaudit\HookHandler', 'itemDeleted'],
        'Ticket'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemDeleted'],
        'Problem'          => ['GlpiPlugin\Securityaudit\HookHandler', 'itemDeleted'],
        'Change'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemDeleted'],
        'Profile'          => ['GlpiPlugin\Securityaudit\HookHandler', 'itemDeleted'],
        'Entity'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemDeleted'],
    ];

    $PLUGIN_HOOKS['item_purge']['securityaudit'] = [
        'User'             => ['GlpiPlugin\Securityaudit\HookHandler', 'itemPurged'],
        'Computer'         => ['GlpiPlugin\Securityaudit\HookHandler', 'itemPurged'],
        'NetworkEquipment' => ['GlpiPlugin\Securityaudit\HookHandler', 'itemPurged'],
        'Software'         => ['GlpiPlugin\Securityaudit\HookHandler', 'itemPurged'],
        'Ticket'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemPurged'],
        'Problem'          => ['GlpiPlugin\Securityaudit\HookHandler', 'itemPurged'],
        'Change'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemPurged'],
        'Profile'          => ['GlpiPlugin\Securityaudit\HookHandler', 'itemPurged'],
        'Entity'           => ['GlpiPlugin\Securityaudit\HookHandler', 'itemPurged'],
    ];

    // Hooks auth
    $PLUGIN_HOOKS['login']['securityaudit']  = ['GlpiPlugin\Securityaudit\HookHandler', 'userLogin'];
    $PLUGIN_HOOKS['logout']['securityaudit'] = ['GlpiPlugin\Securityaudit\HookHandler', 'userLogout'];

    // Menu dans Outils
    if (Session::haveRight('plugin_securityaudit_log', READ)) {
        $PLUGIN_HOOKS['menu_toadd']['securityaudit'] = ['tools' => 'GlpiPlugin\Securityaudit\Dashboard'];
    }
}

function plugin_version_securityaudit() {
    return [
        'name'         => 'SecurityAudit',
        'version'      => PLUGIN_SECURITYAUDIT_VERSION,
        'author'       => 'Mario Prospero',
        'license'      => 'MIT',
        'homepage'     => 'https://github.com/pluginsGLPI/securityaudit',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_SECURITYAUDIT_MIN_GLPI,
                'max' => PLUGIN_SECURITYAUDIT_MAX_GLPI,
            ],
        ],
    ];
}

function plugin_securityaudit_check_prerequisites() {
    if (version_compare(GLPI_VERSION, PLUGIN_SECURITYAUDIT_MIN_GLPI, 'lt')) {
        echo 'Ce plugin nécessite GLPI >= ' . PLUGIN_SECURITYAUDIT_MIN_GLPI;
        return false;
    }
    if (version_compare(GLPI_VERSION, PLUGIN_SECURITYAUDIT_MAX_GLPI, 'ge')) {
        echo 'Ce plugin ne supporte pas GLPI >= ' . PLUGIN_SECURITYAUDIT_MAX_GLPI;
        return false;
    }
    return true;
}

function plugin_securityaudit_check_config() {
    return true;
}
