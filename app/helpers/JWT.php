<?php
class JWT {

    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private static function sign($header, $payload) {
        $secret = JWT_SECRET;
        return self::base64UrlEncode(
            hash_hmac('sha256', "$header.$payload", $secret, true)
        );
    }

  public static function generateAccessToken($user) {
    $header = self::base64UrlEncode(json_encode(['typ'=>'JWT','alg'=>'HS256']));
    
    $payloadData = [
        "user_id" => $user['user_id'],
        "email"   => $user['email'],
        "rt_sig"  => $user['rt_sig'], 
        "type"    => "access",
        "iat"     => time(),
        "exp"     => time() + ACCESS_TOKEN_EXP
    ];
    
    $payload = self::base64UrlEncode(json_encode($payloadData));
    $signature = self::sign($header, $payload);
    return "$header.$payload.$signature";
}
    public static function generateRefreshToken($user) {
        $header = self::base64UrlEncode(json_encode(['typ'=>'JWT','alg'=>'HS256']));
        
        $payloadData = [
            "user_id"=>$user['user_id'],
            "email"=>$user['email'],
            "type"=>"refresh",
            "iat"=>time(),
            "exp"=>time()+REFRESH_TOKEN_EXP
        ];
        
        $payload = self::base64UrlEncode(json_encode($payloadData));
        $signature = self::sign($header,$payload);

        return "$header.$payload.$signature";
    }

    public static function validate($token,$expectedType="access") {
        $parts = explode('.', $token);
        if(count($parts)!=3) return false;

        list($header,$payload,$signature)=$parts;
        $validSignature = self::sign($header,$payload);

        if(!hash_equals($validSignature,$signature)) return false;

        $payloadData=json_decode(self::base64UrlDecode($payload),true);
        if(!$payloadData) return false;

        if($payloadData['type']!=$expectedType) return false;
        if($payloadData['exp'] < time()) return false;

        return $payloadData;
    }
public static function validateSignatureAndType($token, $expectedType = "access") {
    $parts = explode('.', $token);
    if (count($parts) != 3) return false;

    list($header, $payload, $signature) = $parts;
    $validSignature = self::sign($header, $payload);

    if (!hash_equals($validSignature, $signature)) return false;

    $payloadData = json_decode(self::base64UrlDecode($payload), true);
    if (!$payloadData) return false;

    if ($payloadData['type'] != $expectedType) return false;

    
    return $payloadData;
}
}