package com.yourco.web.vulnsamples;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * A02:2025 - Cryptographic Failures
 * OWASP Top 10:2025 第2位
 * 
 * 検出: Semgrep (p/java, p/security-audit)
 */
public class A02_CryptographicFailures {

    /**
     * 脆弱性1: 弱いハッシュアルゴリズム MD5
     * Semgrep autofix: SHA-256 に置換可能
     */
    public String hashPasswordMD5(String password) throws Exception {
        // NG: MD5 は衝突攻撃に脆弱
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * 脆弱性2: 弱いハッシュアルゴリズム SHA-1
     */
    public String hashPasswordSHA1(String password) throws Exception {
        // NG: SHA-1 も非推奨
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * 脆弱性3: 弱い暗号化アルゴリズム DES
     */
    public byte[] encryptDES(String data, String key) throws Exception {
        // NG: DES は56ビット鍵で脆弱
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data.getBytes());
    }

    /**
     * 脆弱性4: ECBモード使用
     */
    public byte[] encryptECB(String data, byte[] key) throws Exception {
        // NG: ECBモードはパターンが漏洩する
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data.getBytes());
    }

    /**
     * 脆弱性5: ハードコードされた暗号化キー
     */
    private static final String SECRET_KEY = "MySecretKey12345";
    
    public byte[] encryptWithHardcodedKey(String data) throws Exception {
        // NG: 鍵がソースコードにハードコード
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data.getBytes());
    }
}

