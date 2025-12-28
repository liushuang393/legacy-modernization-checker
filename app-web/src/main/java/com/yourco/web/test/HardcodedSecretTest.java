package com.yourco.web.test;

import org.springframework.stereotype.Component;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * ハードコードされた秘密情報テスト用クラス
 * 
 * 検出対象: Gitleaks, Semgrep
 * 脆弱性: CWE-798 Hardcoded Credentials
 */
@Component
public class HardcodedSecretTest {

    // NG: ハードコードされたAPIキー（Gitleaksで検出）
    private static final String API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234";
    
    // NG: ハードコードされたデータベースパスワード
    private static final String DB_PASSWORD = "MySecretPassword123!";
    
    // NG: ハードコードされた暗号化キー
    private static final String ENCRYPTION_KEY = "AES256SecretKey1234567890123456";
    
    // NG: ハードコードされたJWTシークレット
    private static final String JWT_SECRET = "jwt-secret-key-for-signing-tokens-very-long-string-here";

    /**
     * 脆弱性: ハードコードされたキーで暗号化
     * 修正方法: 環境変数またはSecret Managerから取得
     */
    public String encryptData(String data) throws Exception {
        // NG: ハードコードされたキーを使用
        SecretKeySpec keySpec = new SecretKeySpec(
            ENCRYPTION_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
    }

    /**
     * 脆弱性: ハードコードされたAPIキーを使用
     * 修正方法: 環境変数から取得
     */
    public String callExternalApi() {
        // NG: ハードコードされたAPIキー
        return "Authorization: Bearer " + API_KEY;
    }

    /**
     * 安全な実装例（参考）
     */
    public String getApiKeySafe() {
        // OK: 環境変数から取得
        return System.getenv("API_KEY");
    }
}

