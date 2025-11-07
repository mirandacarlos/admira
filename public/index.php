<?php

require __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

use App\Controllers\AuthController;

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

header('Content-Type: application/json; charset=utf-8');

$controller = new AuthController();

$authCheck = $controller->getTwoFactorSettings();
if (!empty($authCheck['success'])) {
	header('Location: /settings');
	exit;
}

// Simple routing
if ($method === 'POST' && $uri === '/login') {
	$input = json_decode(file_get_contents('php://input'), true) ?: $_POST;
	$user = $input['user'] ?? $input['username'] ?? '';
	$pass = $input['pass'] ?? $input['password'] ?? '';

	$res = $controller->login((string)$user, (string)$pass);
	echo json_encode($res);
	exit;
}

if ($method === 'POST' && ($uri === '/verify-2fa' || $uri === '/verify-two-factor')) {
	$input = json_decode(file_get_contents('php://input'), true) ?: $_POST;
	$token = $input['token'] ?? $_COOKIE['two_factor_token'] ?? '';
	$code = $input['code'] ?? '';

	$res = $controller->verifyTwoFactor((string)$token, (string)$code);
	echo json_encode($res);
	exit;
}

if ($method === 'POST' && $uri === '/logout') {
	$res = $controller->logout();
	echo json_encode($res);
	exit;
}

// Login form (simple HTML)
if ($method === 'GET' && $uri === '/login') {
	header('Content-Type: text/html; charset=utf-8');
	echo '<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head><body>';
	echo '<h1>Login</h1>';
	echo '<form method="post" action="/login">';
	echo '<label>Username or Email: <input name="username" required></label><br>';
	echo '<label>Password: <input name="password" type="password" required></label><br>';
	echo '<button type="submit">Login</button>';
	echo '</form>';
	echo '<p><a href="/register">Create an account</a></p>';
	echo '</body></html>';
	exit;
}

// Two-factor settings page (requires login)
if ($method === 'GET' && $uri === '/settings') {
	$user = $data['user'];
	$current = $user['two_factor_method'] ?? 'none';

	header('Content-Type: text/html; charset=utf-8');
	echo '<!doctype html><html><head><meta charset="utf-8"><title>2FA Settings</title></head><body>';
	echo '<h1>Two-factor settings</h1>';
	echo '<form method="post" action="/settings">';
	echo '<label><input type="radio" name="two_factor_method" value="none"' . ($current === 'none' ? ' checked' : '') . '> None</label><br>';
	echo '<label><input type="radio" name="two_factor_method" value="email"' . ($current === 'email' ? ' checked' : '') . '> Email (send codes to your registered email)</label><br>';
	echo '<label><input type="radio" name="two_factor_method" value="totp"' . ($current === 'totp' ? ' checked' : '') . '> Authenticator app (TOTP)</label><br>';
	echo '<button type="submit">Save</button>';
	echo '</form>';

	if (!empty($data['totp_provisioning_uri'])) {
		echo '<h2>TOTP already configured</h2>';
		echo '<p>Provisioning URI: <code>' . htmlspecialchars($data['totp_provisioning_uri']) . '</code></p>';
		echo '<p>Secret: <code>' . htmlspecialchars($data['totp_secret']) . '</code></p>';
	}

	echo '<p><a href="/logout">Logout</a></p>';
	echo '</body></html>';
	exit;
}

// Handle update of two-factor settings
if ($method === 'POST' && $uri === '/settings') {
	$input = json_decode(file_get_contents('php://input'), true) ?: $_POST;
	$twoFactor = $input['two_factor_method'] ?? 'none';

	$res = $controller->updateTwoFactorSettings((string)$twoFactor);
	echo json_encode($res);
	exit;
}

// Registration form (simple HTML) and endpoint
if ($method === 'GET' && $uri === '/register') {
	header('Content-Type: text/html; charset=utf-8');
	echo '<!doctype html><html><head><meta charset="utf-8"><title>Register</title></head><body>';
	echo '<h1>Register</h1>';
	echo '<form method="post" action="/register">';
	echo '<label>Username: <input name="username" required></label><br>';
	echo '<label>Email: <input name="email" type="email" required></label><br>';
	echo '<label>Password: <input name="password" type="password" required></label><br>';
	echo '<label>Two-factor: <select name="two_factor_method"><option value="none">None</option><option value="email">Email</option><option value="totp">Authenticator (Google Authenticator)</option></select></label><br>';
	echo '<button type="submit">Register</button>';
	echo '</form>';
	echo '<p><a href="/login">Already have an account? Login</a></p>';
	echo '</body></html>';
	exit;
}

if ($method === 'POST' && $uri === '/register') {
	$input = json_decode(file_get_contents('php://input'), true) ?: $_POST;
	$username = $input['username'] ?? '';
	$email = $input['email'] ?? '';
	$password = $input['password'] ?? '';
	$twoFactor = $input['two_factor_method'] ?? ($input['two_factor'] ?? 'none');

	$res = $controller->register((string)$username, (string)$email, (string)$password, (string)$twoFactor);
	echo json_encode($res);
	exit;
}

// Default: 404
http_response_code(404);
echo json_encode(['success' => false, 'message' => 'Not found']);
