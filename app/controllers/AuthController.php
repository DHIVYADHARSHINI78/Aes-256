<?php
class AuthController {
  
    public function register() {
        $data = $GLOBALS['request_data'];
        if (empty($data['name']) || empty($data['email']) || empty($data['password'])) {
            Response::json(["error" => "Name, email & password required"], 400);
            return;
        }

        $normalizedEmail = strtolower(trim($data['email']));
        $emailEncrypted = AES::encrypt($normalizedEmail);
        $emailHash = AES::generateHash($normalizedEmail);

        $userModel = new User();
        $hashed = password_hash($data['password'], PASSWORD_DEFAULT);

        try {
            $userModel->create($data['name'], $emailEncrypted, $emailHash, $hashed);
            Response::json(["message" => "User created"], 201);
        } catch (Exception $e) {
            Response::json(["error" => "Email exists"], 409);
        }
    }

    public function login() {
        if (session_status() === PHP_SESSION_NONE) session_start();

        $data = $GLOBALS['request_data'];
        $userModel = new User();
        $user = $userModel->findByEmail($data['email']);

        if (!$user || !password_verify($data['password'], $user['password'])) {
            Response::json(['error' => 'Invalid email or password'], 401);
            return;
        }

        $csrfToken = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $csrfToken;
        $_SESSION['user_id'] = $user['id'];

        // FIX: Decrypt email from DB to use in JWT (Warnings avoided)
        $userEmail = isset($user['email_encrypted']) ? AES::decrypt($user['email_encrypted']) : null;

        $refreshToken = JWT::generateRefreshToken(['user_id' => $user['id'], 'email' => $userEmail]);
        $rtSignature = explode('.', $refreshToken)[2];

        $accessToken = JWT::generateAccessToken([
            'user_id' => $user['id'],
            'email'   => $userEmail,
            'rt_sig'  => hash('sha256', $rtSignature)
        ]);

        // Capture User Agent Hash 
     

       $userModel->storeRefreshToken($user['id'], $refreshToken);
     

        setcookie("refreshToken", $refreshToken, [
            'expires' => time() + (int)REFRESH_TOKEN_EXP,
            'path' => "/",
            'httponly' => true,
            'secure' => false,
            'samesite' => 'Lax'
        ]);

        Response::json([
            "access_token" => $accessToken,
            "csrf_token"   => $csrfToken,
            "message"      => "Login successful"
        ]);
    }

    public function refresh() {
        $headers = getallheaders();
        $auth = $headers['Authorization'] ?? $headers['authorization'] ?? null;
        if (!$auth || !preg_match('/Bearer\s(\S+)/', $auth, $m)) {
            Response::json(["error" => "Access token required"], 401);
            return;
        }
        $accessToken = $m[1];

        $userData = JWT::validateSignatureAndType($accessToken, "access");
        if (!$userData) {
            Response::json(["error" => "Invalid access token"], 401);
            return;
        }

       

        $refreshToken = $_COOKIE['refreshToken'] ?? null;
        if (!$refreshToken) {
            Response::json(['error' => 'Session expired or Loginin again'], 401);
            return;
        }

        $userModel = new User();
        $user = $userModel->findByRefreshToken($refreshToken);
        if (!$user) {
            Response::json(['error' => 'Invalid refresh token'], 403);
            return;
        }

 
        $userEmail = isset($user['email_encrypted']) ? AES::decrypt($user['email_encrypted']) : null;

        $newRefreshToken = JWT::generateRefreshToken([
            'user_id' => $user['id'], 
            'email' => $userEmail
        ]);

        $rtSignature = explode('.', $newRefreshToken)[2];
        $newAccessToken = JWT::generateAccessToken([
            'user_id' => $user['id'],
            'email'   => $userEmail,
            'rt_sig'  => hash('sha256', $rtSignature)
        ]);

   
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $userAgentHash = hash('sha256', $userAgent);
        $userModel->storeRefreshToken($user['id'], $newRefreshToken, $userAgentHash);

        setcookie("refreshToken", $newRefreshToken, [
            'expires' => time() + (int)REFRESH_TOKEN_EXP,
            'path' => "/",
            'httponly' => true,
            'secure' => false,
            'samesite' => 'Lax'
        ]);

        Response::json([
            "access_token" => $newAccessToken,
            "message" => "Token refreshed successfully"
        ]);
    }

    public function logout() {
        if (session_status() === PHP_SESSION_NONE) session_start();
        $userId = $GLOBALS['user']['user_id'] ?? $_SESSION['user_id'] ?? null;

        if ($userId) {
            $userModel = new User();
            $userModel->storeRefreshToken($userId, null);
        }

        setcookie("refreshToken", "", [
            'expires' => time() - 3600,
            'path' => "/",
            'httponly' => true,
            'secure' => false,
            'samesite' => 'Lax'
        ]);

        session_unset();
        session_destroy();
        Response::json(["message" => "Logged out successfully"]);
    }
}