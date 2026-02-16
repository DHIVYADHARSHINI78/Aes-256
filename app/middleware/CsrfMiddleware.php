<?php
class CsrfMiddleware {
    public static function handle() {
        if (session_status() === PHP_SESSION_NONE) session_start();

        $currentUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
   $excludedRoutes = ['/api/login', '/api/register', '/api/refresh', '/api/logout'];

        foreach ($excludedRoutes as $route) {
            if (strpos($currentUri, $route) !== false) {
                return;
            }
        }

        if (in_array($_SERVER['REQUEST_METHOD'], ['GET','POST', 'PUT', 'DELETE', 'PATCH'])) {
            $headers = getallheaders();
            $receivedToken = $headers['X-CSRF-Token'] ?? $headers['x-csrf-token'] ?? null;
            $storedToken = $_SESSION['csrf_token'] ?? null;

            if (!$receivedToken || !$storedToken || !hash_equals($storedToken, $receivedToken)) {
                Response::json(["error" => "CSRF Token mismatch or missing"], 403);
                exit;
            }
        }
    }
}