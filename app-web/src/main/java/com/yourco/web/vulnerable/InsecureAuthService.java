package com.yourco.web.vulnerable;

import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

/**
 * 脆弱な認証サービス（テスト用）
 * 暗号化・認証に関する脆弱性サンプル
 */
@Service
public class InsecureAuthService {

    // [VULN-012] ハードコードされた暗号鍵 - Gitleaks/Semgrep検出対象
    private static final String SECRET_KEY = "MySecretKey12345";
    private static final String INIT_VECTOR = "RandomInitVector";

    // [VULN-013] 安全でないパスワード比較 - Semgrep検出対象
    public boolean validatePassword(String input, String stored) {
        // 危険：タイミング攻撃に脆弱な文字列比較
        return input.equals(stored);
    }

    // [VULN-014] ECBモード使用 - Semgrep検出対象
    public String encryptECB(String plaintext) throws Exception {
        // 危険：ECBモードはパターンが漏洩する
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes()));
    }

    // [VULN-015] 弱い暗号化アルゴリズム（DES） - Semgrep検出対象
    public String encryptDES(String plaintext) throws Exception {
        // 危険：DESは56ビット鍵で脆弱
        SecretKeySpec keySpec = new SecretKeySpec("12345678".getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes()));
    }

    // [VULN-016] 固定IVの使用 - Semgrep検出対象
    public String encryptWithFixedIV(String plaintext) throws Exception {
        // 危険：IVは毎回ランダムに生成すべき
        SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(INIT_VECTOR.getBytes());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes()));
    }

    // [VULN-017] null許容のセキュリティチェック - Semgrep検出対象
    public boolean isAdmin(String role) {
        // 危険：nullの場合にtrueを返す可能性
        if (role == null) {
            return false;
        }
        return "ADMIN".equalsIgnoreCase(role);
    }

    // [VULN-018] 例外情報の漏洩 - Semgrep検出対象
    public String processData(String data) {
        try {
            // 何らかの処理
            return data.toUpperCase();
        } catch (Exception e) {
            // 危険：スタックトレースをユーザーに返す
            return "Error: " + e.getMessage() + "\n" + java.util.Arrays.toString(e.getStackTrace());
        }
    }
}

