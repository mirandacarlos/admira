<?php

namespace App\Controllers;

use App\Services\AuthService;
use Exception;
use App\Services\TotpService;

class AuthController
{
    private AuthService $authService;

    public function __construct()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $this->authService = new AuthService();
    }

    /**
     * Handle user authentication
     * 
     * @param string $user Username or email
     * @param string $pass Password
     * @return array Response with authentication status and message
     */
    public function login(string $user, string $pass): array
    {
        try {
            // Input validation
            if (empty($user) || empty($pass)) {
                return [
                    'success' => false,
                    'message' => 'Username and password are required'
                ];
            }

            // Sanitize input
            $user = filter_var($user, FILTER_SANITIZE_STRING);
            
            // Rate limiting check
            if ($this->isRateLimitExceeded($_SERVER['REMOTE_ADDR'])) {
                return [
                    'success' => false,
                    'message' => 'Too many login attempts. Please try again later.'
                ];
            }

            // Validate credentials
            $userData = $this->authService->validateCredentials($user, $pass);

            if (!$userData) {
                $this->incrementFailedAttempts($_SERVER['REMOTE_ADDR']);
                return [
                    'success' => false,
                    'message' => 'Invalid credentials'
                ];
            }

            // Branch by user's 2FA preference
            $method = $userData->getTwoFactorMethod();
            if ($method === 'none') {
                // Create session and return success
                $sessionId = $this->authService->createSession($userData);
                $this->setSecureCookie('session_id', $sessionId);
                return [
                    'success' => true,
                    'message' => 'Authentication successful',
                    'user' => $userData->toArray()
                ];
            }

            if ($method === 'email') {
                // Generate 2FA token and send code via email
                $twoFactorToken = $this->authService->createTwoFactorToken($userData);

                // Set a short-lived cookie to keep token on client (also returned in payload)
                $this->setSecureCookie('two_factor_token', $twoFactorToken, time() + 600);

                return [
                    'success' => false,
                    'two_factor_required' => true,
                    'two_factor_method' => 'email',
                    'message' => 'A verification code was sent to your email',
                    'two_factor_token' => $twoFactorToken
                ];
            }

            if ($method === 'totp') {
                // Require user to provide TOTP code from their authenticator
                return [
                    'success' => false,
                    'two_factor_required' => true,
                    'two_factor_method' => 'totp',
                    'message' => 'Enter the code from your authenticator app.'
                ];
            }

            // Fallback
            return ['success' => false, 'message' => 'Unsupported two-factor configuration'];

        } catch (Exception $e) {
            // Log the error (implement your logging system)
            error_log("Authentication error: " . $e->getMessage());
            
            return [
                'success' => false,
                'message' => 'An error occurred during authentication'
            ];
        }
    }

    /**
     * Check if user has exceeded rate limit
     */
    private function isRateLimitExceeded(string $ip): bool
    {
        $attempts = isset($_SESSION['login_attempts'][$ip]) 
            ? $_SESSION['login_attempts'][$ip] 
            : ['count' => 0, 'timestamp' => time()];

        // Reset attempts if more than 15 minutes have passed
        if (time() - $attempts['timestamp'] > 900) {
            $_SESSION['login_attempts'][$ip] = ['count' => 0, 'timestamp' => time()];
            return false;
        }

        return $attempts['count'] >= 5;
    }

    /**
     * Increment failed login attempts
     */
    private function incrementFailedAttempts(string $ip): void
    {
        if (!isset($_SESSION['login_attempts'][$ip])) {
            $_SESSION['login_attempts'][$ip] = ['count' => 0, 'timestamp' => time()];
        }

        $_SESSION['login_attempts'][$ip]['count']++;
    }

    /**
     * Set secure HTTP-only cookie
     */
    private function setSecureCookie(string $name, string $value, ?int $expiry = null): void
    {
        $secure = isset($_SERVER['HTTPS']);
        $httpOnly = true;
        $sameSite = 'Strict';
        $expiry = $expiry ?? (time() + (30 * 24 * 60 * 60)); // default 30 days

        setcookie(
            $name,
            $value,
            [
                'expires' => $expiry,
                'path' => '/',
                'domain' => $_SERVER['HTTP_HOST'] ?? '',
                'secure' => $secure,
                'httponly' => $httpOnly,
                'samesite' => $sameSite
            ]
        );
    }

    /**
     * Verify a two-factor token + code. If valid, create session and return auth response.
     */
    public function verifyTwoFactor(string $token, string $code): array
    {
        try {
            if (empty($token) || empty($code)) {
                return ['success' => false, 'message' => 'Token and code are required'];
            }

            $result = $this->authService->verifyTwoFactorToken($token, $code);

            if (!isset($result['status'])) {
                return ['success' => false, 'message' => 'Invalid response from verification'];
            }

            if ($result['status'] === 'locked') {
                return ['success' => false, 'message' => 'Too many failed attempts. The verification token has been invalidated.'];
            }

            if ($result['status'] !== 'ok' || !($result['user'] ?? null)) {
                return ['success' => false, 'message' => 'Invalid or expired verification code'];
            }

            $user = $result['user'];

            // Create session and set session cookie
            $sessionId = $this->authService->createSession($user);
            $this->setSecureCookie('session_id', $sessionId);

            // Clear any two_factor_token cookie
            $this->setSecureCookie('two_factor_token', '', time() - 3600);

            return [
                'success' => true,
                'message' => 'Authentication successful',
                'user' => $user->toArray()
            ];

        } catch (Exception $e) {
            error_log('2FA verification error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'An error occurred during verification'];
        }
    }

    /**
     * Register a new user with optional 2FA preference.
     * Returns array with success and (for TOTP) provisioning data.
     */
    public function register(string $username, string $email, string $password, string $twoFactorMethod = 'none'): array
    {
        try {
            // Basic validation
            if (empty($username) || empty($email) || empty($password)) {
                return ['success' => false, 'message' => 'Username, email and password are required'];
            }

            $username = filter_var($username, FILTER_SANITIZE_STRING);
            $email = filter_var($email, FILTER_VALIDATE_EMAIL);
            if ($email === false) {
                return ['success' => false, 'message' => 'Invalid email'];
            }

            $twoFactorMethod = in_array($twoFactorMethod, ['none', 'email', 'totp']) ? $twoFactorMethod : 'none';

            $totpSecret = null;
            $provision = null;
            if ($twoFactorMethod === 'totp') {
                $totp = new TotpService();
                $totpSecret = $totp->generateSecret();
                $provision = $totp->getProvisioningUri($username, $totpSecret, $_ENV['APP_NAME'] ?? 'Admira');
            }

            $user = $this->authService->registerUser($username, $email, $password, $twoFactorMethod, $totpSecret);

            $response = ['success' => true, 'message' => 'User registered', 'user' => $user->toArray()];
            if ($twoFactorMethod === 'totp') {
                $response['totp_provisioning_uri'] = $provision;
                $response['totp_secret'] = $totpSecret; // consider not returning secret in production; return only provisioning URI or QR
            }

            return $response;
        } catch (\Exception $e) {
            error_log('Registration error: ' . $e->getMessage());
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }

    /**
     * Logout user and destroy session
     */
    public function logout(): array
    {
        try {
            if (isset($_COOKIE['session_id'])) {
                // Remove session from database
                $this->authService->invalidateSession($_COOKIE['session_id']);
                
                // Remove cookie
                $this->setSecureCookie('session_id', '', time() - 3600);
            }

            return [
                'success' => true,
                'message' => 'Logged out successfully'
            ];

        } catch (Exception $e) {
            error_log("Logout error: " . $e->getMessage());
            
            return [
                'success' => false,
                'message' => 'An error occurred during logout'
            ];
        }
    }
}
