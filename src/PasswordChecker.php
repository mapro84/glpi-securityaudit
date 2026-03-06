<?php

namespace GlpiPlugin\Securityaudit;

/**
 * Détection et scoring des mots de passe faibles
 */
class PasswordChecker {

    // Liste des 50 mots de passe les plus courants
    private static array $commonPasswords = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321',
        'superman', 'qazwsx', 'michael', 'football', 'password1',
        'azerty', 'soleil', 'bonjour', 'glpi', 'admin',
        'administrator', 'root', 'toor', 'test', 'changeme',
    ];

    /**
     * Analyse un mot de passe et retourne un score 0-100
     */
    public static function score(string $password): array {
        $issues = [];
        $score  = 100;

        $len = strlen($password);

        // Longueur
        if ($len < 8)  { $issues[] = 'Trop court (< 8 caractères)';          $score -= 40; }
        elseif ($len < 10) { $issues[] = 'Court (< 10 caractères)';           $score -= 15; }
        elseif ($len < 12) { $score -= 5; }

        // Complexité
        if (!preg_match('/[A-Z]/', $password)) { $issues[] = 'Aucune majuscule';   $score -= 15; }
        if (!preg_match('/[a-z]/', $password)) { $issues[] = 'Aucune minuscule';   $score -= 15; }
        if (!preg_match('/[0-9]/', $password)) { $issues[] = 'Aucun chiffre';      $score -= 15; }
        if (!preg_match('/[\W_]/', $password)) { $issues[] = 'Aucun caractère spécial'; $score -= 20; }

        // Patterns répétitifs
        if (preg_match('/(.)\1{2,}/', $password)) {
            $issues[] = 'Caractères répétés (ex: aaa)';
            $score -= 15;
        }
        if (preg_match('/^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwe|azer)+$/i', $password)) {
            $issues[] = 'Séquence triviale';
            $score -= 25;
        }

        // Mots de passe courants
        if (in_array(strtolower($password), self::$commonPasswords, true)) {
            $issues[] = 'Mot de passe trop commun';
            $score = min($score, 10);
        }

        return [
            'score'  => max(0, $score),
            'issues' => $issues,
            'level'  => self::level(max(0, $score)),
        ];
    }

    /**
     * Niveau humain
     */
    public static function level(int $score): string {
        if ($score >= 80) return 'Fort';
        if ($score >= 60) return 'Acceptable';
        if ($score >= 40) return 'Faible';
        return 'Très faible';
    }

    /**
     * Appelé depuis HookHandler lors d'un changement de mot de passe User
     */
    public static function checkAndStore(int $userId, string $password): void {
        global $DB;

        $result = self::score($password);

        // Upsert dans la table
        $exists = $DB->request([
            'FROM'  => 'glpi_plugin_securityaudit_passwords',
            'WHERE' => ['users_id' => $userId],
        ]);

        $data = [
            'users_id'       => $userId,
            'check_date'     => date('Y-m-d H:i:s'),
            'strength_score' => $result['score'],
            'issues'         => json_encode($result['issues'], JSON_UNESCAPED_UNICODE),
            'notified'       => 0,
        ];

        if ($exists->count() > 0) {
            $DB->update('glpi_plugin_securityaudit_passwords', $data, ['users_id' => $userId]);
        } else {
            $DB->insert('glpi_plugin_securityaudit_passwords', $data);
        }

        // Créer une alerte si score < seuil config
        $minScore = (int) Config::getConfig('weak_password_min_score', 60);
        if ($result['score'] < $minScore) {
            HookHandler::createAlert(
                'weak_password',
                'warning',
                "Mot de passe faible détecté (score: {$result['score']}/100) pour user#{$userId} : " . implode(', ', $result['issues']),
                $userId
            );
        }
    }

    /**
     * Retourne les utilisateurs avec mot de passe faible
     */
    public static function getWeakPasswordUsers(int $minScore = 60): array {
        global $DB;

        $result = $DB->request([
            'FROM'    => 'glpi_plugin_securityaudit_passwords',
            'WHERE'   => ['strength_score' => ['<', $minScore]],
            'ORDER'   => ['strength_score ASC'],
        ]);

        return iterator_to_array($result);
    }
}
