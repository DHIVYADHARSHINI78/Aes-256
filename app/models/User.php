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

    $stmt1 = $this->db->prepare("DELETE FROM refresh_tokens WHERE user_id = ?");
    $stmt1->execute([$userId]);

   
    if ($refreshToken) {
        $tokenHash = password_hash($refreshToken, PASSWORD_BCRYPT);
        $expiresAt = date('Y-m-d H:i:s', time() + REFRESH_TOKEN_EXP);
        $createdAt = date('Y-m-d H:i:s');

  
        $stmt3 = $this->db->prepare("INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)");
        return $stmt3->execute([$userId, $tokenHash, $expiresAt, $createdAt]);
    }
    return true;
}

public function create($name, $emailEncrypted, $emailHash, $password) {
    $stmt = $this->db->prepare("INSERT INTO users (name, email_encrypted, email_hash, password) VALUES (?, ?, ?, ?)");
    return $stmt->execute([$name, $emailEncrypted, $emailHash, $password]);
}

public function emailExists($email) {
    $hash = AES::generateHash(strtolower(trim($email)));
    $stmt = $this->db->prepare("SELECT id FROM users WHERE email_hash = ?");
    $stmt->execute([$hash]);
    return $stmt->fetch(PDO::FETCH_ASSOC) !== false;
}

public function findByEmail($email) {
    $hash = AES::generateHash(strtolower(trim($email)));
    $stmt = $this->db->prepare("SELECT * FROM users WHERE email_hash = ?");
    $stmt->execute([$hash]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($user) {
        $user['email'] = AES::decrypt($user['email_encrypted']);
    }
    return $user;
}

    public function getLatestTokenHash($userId) {
    
    $stmt = $this->db->prepare("SELECT token_hash FROM refresh_tokens WHERE user_id = ? ORDER BY id DESC LIMIT 1");
    $stmt->execute([$userId]);
    return $stmt->fetchColumn(); 
}



public function invalidateSession($userId) {
    $stmt = $this->db->prepare("DELETE FROM refresh_tokens WHERE user_id = ?");
    $stmt->execute([$userId]);
}
}