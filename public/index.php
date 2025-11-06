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

// Default: 404
http_response_code(404);
echo json_encode(['success' => false, 'message' => 'Not found']);