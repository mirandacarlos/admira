<?php

namespace App\Services;

use App\Models\User;
use PDO;
use PDOException;
use App\Services\MailService;

class AuthService
{
    private PDO $db;

    public function __construct()
    {
        $this->initDatabase();
    }

    private function initDatabase(): void
    {
        try {
            $this->db = new PDO(
                "mysql:host=" . $_ENV['DB_HOST'] . ";dbname=" . $_ENV['DB_NAME'],
                $_ENV['DB_USER'],
                $_ENV['DB_PASS']
            );
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            throw new \RuntimeException("Database connection failed: " . $e->getMessage());
        }
    }

    public function validateCredentials(string $username, string $password): ?User
    {
        $stmt = $this->db->prepare("
            SELECT * FROM users 
            WHERE (username = :username OR email = :username) 
            LIMIT 1
        ");
        
        $stmt->execute(['username' => $username]);
        $userData = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userData) {
            return null;
        }

        if (!password_verify($password, $userData['password'])) {
            return null;
        }

        return new User($userData);
    }

    /**
     * Invalidate a session by its id
     */
    public function invalidateSession(string $sessionId): void
    {
        $stmt = $this->db->prepare("DELETE FROM user_sessions WHERE session_id = :session_id");
        $stmt->execute(['session_id' => $sessionId]);
    }

    /**
     * Create a two-factor token and email the code to the user
     * Returns the token (should be kept short-lived and secret)
     */
    public function createTwoFactorToken(User $user): string
    {
        $token = bin2hex(random_bytes(16));
        $code = random_int(100000, 999999); // 6-digit code
        $codeHash = password_hash((string)$code, PASSWORD_DEFAULT);
        $expiry = date('Y-m-d H:i:s', time() + 600); // 10 minutes

        $stmt = $this->db->prepare("INSERT INTO two_factor_codes (user_id, token, code_hash, expires_at) VALUES (:user_id, :token, :code_hash, :expires_at)");
        $stmt->execute([
            'user_id' => $user->getId(),
            'token' => $token,
            'code_hash' => $codeHash,
            'expires_at' => $expiry
        ]);

        // Send email with the plain code
        try {
            $mailer = new MailService();
            $subject = 'Your verification code';
            $body = "Your verification code is: " . $code . "\nThis code expires in 10 minutes.";
            $mailer->send($user->getEmail(), $subject, $body);
        } catch (\Exception $e) {
            // Logging the mailing error; do not expose to user
            error_log('Failed to send 2FA email: ' . $e->getMessage());
        }

        return $token;
    }

    /**
     * Verify a two-factor token and code. Returns the User on success, null otherwise.
     */
    public function verifyTwoFactorToken(string $token, string $code): ?User
    {
        $stmt = $this->db->prepare("SELECT * FROM two_factor_codes WHERE token = :token AND expires_at > NOW() LIMIT 1");
        $stmt->execute(['token' => $token]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            return null;
        }

        if (!password_verify((string)$code, $row['code_hash'])) {
            return null;
        }

        // Fetch user
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = :id LIMIT 1");
        $stmt->execute(['id' => $row['user_id']]);
        $userData = $stmt->fetch(PDO::FETCH_ASSOC);

        // Invalidate the used 2FA token
        $del = $this->db->prepare("DELETE FROM two_factor_codes WHERE id = :id");
        $del->execute(['id' => $row['id']]);

        return $userData ? new User($userData) : null;
    }

    public function createSession(User $user): string
    {
        $sessionId = bin2hex(random_bytes(32));
        $expiryTime = time() + (30 * 24 * 60 * 60); // 30 days

        $stmt = $this->db->prepare("
            INSERT INTO user_sessions (user_id, session_id, expires_at) 
            VALUES (:user_id, :session_id, :expires_at)
        ");

        $stmt->execute([
            'user_id' => $user->getId(),
            'session_id' => $sessionId,
            'expires_at' => date('Y-m-d H:i:s', $expiryTime)
        ]);

        return $sessionId;
    }

    public function validateSession(string $sessionId): ?User
    {
        $stmt = $this->db->prepare("
            SELECT u.* FROM users u
            INNER JOIN user_sessions s ON u.id = s.user_id
            WHERE s.session_id = :session_id
            AND s.expires_at > NOW()
            LIMIT 1
        ");

        $stmt->execute(['session_id' => $sessionId]);
        $userData = $stmt->fetch(PDO::FETCH_ASSOC);

        return $userData ? new User($userData) : null;
    }
}