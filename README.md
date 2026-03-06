# SecurityAudit - Plugin GLPI 11

Plugin de sécurité complet pour GLPI 11.0.x

## Fonctionnalités

- 📋 **Journal d'audit** — Qui a fait quoi, quand, depuis quelle IP
- 🔔 **Alertes temps réel** — Suppressions massives, connexions suspectes, actions critiques
- 🔑 **Détection mots de passe faibles** — Score 0-100, liste des problèmes
- 📊 **Tableau de bord sécurité** — Vue d'ensemble, KPIs, dernières alertes

## Structure des fichiers

```
plugins/securityaudit/
├── setup.php                  ← Hooks GLPI + autoloader (PAS de 'use' ici !)
├── hook.php                   ← Install/Uninstall + création tables
├── securityaudit.xml          ← Manifest plugin
├── src/
│   ├── HookHandler.php        ← Capture tous les événements GLPI
│   ├── PasswordChecker.php    ← Scoring mots de passe
│   ├── Config.php             ← Gestion configuration
│   └── Dashboard.php          ← Stats + menu
└── front/
    ├── dashboard.php          ← Tableau de bord principal
    ├── log.php                ← Journal d'audit avec filtres
    ├── alert.php              ← Alertes de sécurité
    ├── password.php           ← Utilisateurs mots de passe faibles
    └── config.form.php        ← Configuration plugin
```

## Installation

### 1. Copier les fichiers

```bash
sudo cp -r securityaudit/ /var/www/glpi/plugins/
sudo chown -R www-data:www-data /var/www/glpi/plugins/securityaudit/
sudo chmod -R 755 /var/www/glpi/plugins/securityaudit/
```

### 2. Vider le cache

```bash
sudo -u www-data rm -rf /var/www/glpi/files/_cache/*
```

### 3. Vérifier la syntaxe PHP

```bash
php -l /var/www/glpi/plugins/securityaudit/setup.php
php -l /var/www/glpi/plugins/securityaudit/hook.php
# → "No syntax errors detected" attendu
```

### 4. Installer via console (recommandé)

```bash
cd /var/www/glpi
sudo -u www-data php bin/console plugin:install securityaudit
sudo -u www-data php bin/console plugin:enable securityaudit
```

### 5. OU via l'interface web

```
Setup → Plugins → SecurityAudit → Installer → Activer
```

## Règles importantes GLPI 11

| Fichier | Contenu autorisé |
|---------|-----------------|
| `setup.php` | `plugin_init_*`, `plugin_version_*`, `plugin_*_check_*` SEULEMENT — **aucun `use`** |
| `hook.php` | `plugin_*_install()` et `plugin_*_uninstall()` SEULEMENT — SQL en **guillemets simples** |
| `src/*.php` | Classes PHP avec namespace `GlpiPlugin\Securityaudit` |
| `front/*.php` | Pages affichage, commencent par `include('../../../inc/includes.php')` |

## Configuration

Accès : `Outils → SecurityAudit → Configuration`

| Paramètre | Défaut | Description |
|-----------|--------|-------------|
| Rétention logs | 90 jours | Durée conservation des logs |
| Score minimum MDP | 60/100 | En dessous = alerte mot de passe faible |
| Alerte suppression massive | Oui | Alerte si >10 suppressions en 5 min |
| Alerte connexions échouées | Oui | Alerte après 3 échecs |

## Droits GLPI

| Droit | Description |
|-------|-------------|
| `plugin_securityaudit_log` | Voir les journaux d'audit |
| `plugin_securityaudit_alert` | Voir et gérer les alertes |
| `plugin_securityaudit_config` | Modifier la configuration |

## Dépannage

### "Plugin has no install function"
→ Vérifier `hook.php` : la fonction `plugin_securityaudit_install()` doit exister et ne pas avoir d'erreur de syntaxe.
```bash
php -l plugins/securityaudit/hook.php
```

### GLPI ne charge pas le plugin
→ Vérifier `setup.php` : aucun `use GlpiPlugin\...` en dehors des fonctions, aucun appel de classe.

### Erreur fatale au chargement
→ Vider le cache : `sudo -u www-data rm -rf /var/www/glpi/files/_cache/*`
