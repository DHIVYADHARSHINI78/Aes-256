<?php
class AuthMiddleware {
    public static function handle() {
        $headers = getallheaders();
        $auth = $headers['Authorization'] ?? $headers['authorization'] ?? null;

        if (!$auth || !preg_match('/Bearer\s(\S+)/', $auth, $m)) {
            Response::json(["error" => "Token missing"], 401);
        }

        $token = $m[1];
        $userData = JWT::validate($token, "access");

        if (!$userData) {
            Response::json(["error" => "Invalid or expired token"], 401);
        }

        // DB check-la problem irundha, ippo cookie mattum check pannunga
        $refreshToken = $_COOKIE['refreshToken'] ?? null;
        if (!$refreshToken) {
            Response::json(["error" => "Refresh token  missing"], 401);
        }

        return $userData;
    }
}