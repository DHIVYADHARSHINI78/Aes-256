<?php
class User {
    private $db;

    public function __construct() {
        $this->db = Database::getInstance();
    }
public function isSessionValid($userId, $refreshToken) {
    if (!$refreshToken) return false;
    $storedHash = $this->getLatestTokenHash($userId);
    return password_verify($refreshToken, $storedHash);
}
    
    public function findByRefreshToken($plainToken) {
    $sql = "SELECT rt.*, u.* FROM users u 
            JOIN refresh_tokens rt ON u.id = rt.user_id 
            WHERE rt.expires_at > NOW()";
    $stmt = $this->db->prepare($sql);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as $row) {
        if (password_verify($plainToken, $row['token_hash'])) {
            return $row;
        }
    }
    return null;
}
public function storeRefreshToken($userId, $refreshToken) {
    // 1. Pazhaya tokens-a delete pannuvom
    $stmt1 = $this->db->prepare("DELETE FROM refresh_tokens WHERE user_id = ?");
    $stmt1->execute([$userId]);

    // 2. Pudhu token irundha insert pannuvom
    if ($refreshToken) {
        $tokenHash = password_hash($refreshToken, PASSWORD_BCRYPT);
        $expiresAt = date('Y-m-d H:i:s', time() + REFRESH_TOKEN_EXP);
        $createdAt = date('Y-m-d H:i:s');

        // Column names check pannunga (user_id, token_hash, expires_at, created_at)
        $stmt3 = $this->db->prepare("INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)");
        return $stmt3->execute([$userId, $tokenHash, $expiresAt, $createdAt]);
    }
    return true;
}

public function create($name, $emailEncrypted, $emailHash, $password) {
    $stmt = $this->db->prepare("INSERT INTO users (name, email_encrypted, email_hash, password) VALUES (?, ?, ?, ?)");
    return $stmt->execute([$name, $emailEncrypted, $emailHash, $password]);
}

// For duplicate check (no decryption needed)
public function emailExists($email) {
    $hash = AES::generateHash(strtolower(trim($email)));
    $stmt = $this->db->prepare("SELECT id FROM users WHERE email_hash = ?");
    $stmt->execute([$hash]);
    return $stmt->fetch(PDO::FETCH_ASSOC) !== false;
}

// For login (decrypt to verify)
public function findByEmail($email) {
    $hash = AES::generateHash(strtolower(trim($email)));
    $stmt = $this->db->prepare("SELECT * FROM users WHERE email_hash = ?");
    $stmt->execute([$hash]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($user) {
        $user['email'] = AES::decrypt($user['email_encrypted']); // Decrypt for use
    }
    return $user;
}

    public function getLatestTokenHash($userId) {
    
    $stmt = $this->db->prepare("SELECT token_hash FROM refresh_tokens WHERE user_id = ? ORDER BY id DESC LIMIT 1");
    $stmt->execute([$userId]);
    return $stmt->fetchColumn(); 
}
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

    // Existing: Check refresh token
    $userModel = new User();
    $sessionValid = $userModel->isSessionValid($userData['user_id'], $_COOKIE['refreshToken'] ?? null);
    if (!$sessionValid) {
        Response::json(["error" => "Session invalid or token stolen"], 401);
    }

    // NEW: Soft IP and User Agent Validation
    $currentIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $currentUserAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $currentUserAgentHash = hash('sha256', $currentUserAgent);

    $storedData = $userModel->getStoredSessionData($userData['user_id']);  // Fetch stored IP/agent
    $storedIp = $storedData['initial_ip'] ?? 'unknown';
    $storedUserAgentHash = $storedData['user_agent_hash'] ?? '';

    $riskScore = 0;  // Initialize risk score

    // Check IP change
    if ($storedIp !== $currentIp && $storedIp !== 'unknown') {
        self::logSuspiciousActivity($userData['user_id'], "IP changed from $storedIp to $currentIp");
        $riskScore += 2;  // Moderate risk
    }

    // Check User Agent change
    if ($storedUserAgentHash !== $currentUserAgentHash && !empty($storedUserAgentHash)) {
        self::logSuspiciousActivity($userData['user_id'], "User agent changed");
        $riskScore += 3;  // High risk (device switch)
    }

    // Take action based on risk
    if ($riskScore > 5) {
        // High risk: Force re-login
        $userModel->invalidateSession($userData['user_id']);  // Clear refresh token
        Response::json(["error" => "Suspicious activity detected. Please log in again."], 401);
    } elseif ($riskScore > 0) {
        // Low/medium risk: Log and allow, but warn (optional)
        error_log("Low risk activity for user {$userData['user_id']}: Risk score $riskScore");
    }

    return $userData;
}




private static function logSuspiciousActivity($userId, $message) {
    $logMessage = date('Y-m-d H:i:s') . " - User $userId: $message\n";
    file_put_contents(__DIR__ . '/../../logs/suspicious_activity.log', $logMessage, FILE_APPEND);
}
public function invalidateSession($userId) {
    $stmt = $this->db->prepare("DELETE FROM refresh_tokens WHERE user_id = ?");
    $stmt->execute([$userId]);
}
}