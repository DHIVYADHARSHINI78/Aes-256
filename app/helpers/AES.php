<?php
class AES {
    private static $cipher = 'aes-256-cbc';
    private static $keyLength = 32; // 256 bits

  private static function getKey($envVar) {
        if (!defined($envVar)) {
            throw new Exception("Environment variable $envVar not set");
        }
        $key = constant($envVar);
      
        return substr(hash('sha256', $key, true), 0, self::$keyLength);
    }
    public static function encrypt($plainText) {
        $key = self::getKey('AES_SECRET');
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::$cipher)); // Unique IV per encryption
        $encrypted = openssl_encrypt($plainText, self::$cipher, $key, 0, $iv);
        if ($encrypted === false) {
            throw new Exception('Encryption failed');
        }
        // Return IV + encrypted data (base64 encoded for DB storage)
        return base64_encode($iv . $encrypted);
    }

    // Decrypt data
    public static function decrypt($encryptedText) {
        $key = self::getKey('AES_SECRET');
        $data = base64_decode($encryptedText);
        $ivLength = openssl_cipher_iv_length(self::$cipher);
        $iv = substr($data, 0, $ivLength);
        $encrypted = substr($data, $ivLength);
        $decrypted = openssl_decrypt($encrypted, self::$cipher, $key, 0, $iv);
        if ($decrypted === false) {
            throw new Exception('Decryption failed');
        }
        return $decrypted;
    }

    // Generate blind index hash for searching (HMAC-SHA256)
    public static function generateHash($plainText) {
        $key = self::getKey('HASH_SECRET');
        return hash_hmac('sha256', strtolower(trim($plainText)), $key);
    }



  
}