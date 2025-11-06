<?php

require __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

use App\Controllers\AuthController;

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

header('Content-Type: application/json; charset=utf-8');

$controller = new AuthController();

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
	echo '</form></body></html>';
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