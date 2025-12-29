package com.yourco.web.vulnsamples;

import org.springframework.web.bind.annotation.*;
import java.security.SecureRandom;
import java.util.Random;

/**
 * A07:2025 - Identification and Authentication Failures
 * OWASP Top 10:2025 第7位
 * 
 * 検出: Semgrep (p/java, p/security-audit)
 */
@RestController
@RequestMapping("/api/a07")
public class A07_AuthenticationFailures {

    /**
     * 脆弱性1: ハードコードされた認証情報
     */
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "admin123";  // NG: ハードコード

    @PostMapping("/admin-login")
    public String adminLogin(@RequestParam String user, @RequestParam String pass) {
        if (ADMIN_USERNAME.equals(user) && ADMIN_PASSWORD.equals(pass)) {
            return "Admin access granted";
        }
        return "Access denied";
    }

    /**
     * 脆弱性2: 弱い乱数生成器
     */
    @GetMapping("/token")
    public String generateToken() {
        // NG: 予測可能な乱数
        Random random = new Random();
        return String.valueOf(random.nextLong());
    }

    /**
     * 脆弱性3: パスワードの平文保存
     */
    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password) {
        // NG: パスワードを平文で保存（ログ出力）
        System.out.println("Registering user: " + username + " with password: " + password);
        return "User registered";
    }

    /**
     * 脆弱性4: 弱いパスワードポリシー
     */
    @PostMapping("/set-password")
    public String setPassword(@RequestParam String password) {
        // NG: パスワード強度チェックなし
        if (password.length() < 4) {
            return "Password too short";
        }
        return "Password set";
    }

    /**
     * 脆弱性5: JWT秘密鍵のハードコード
     */
    private static final String JWT_SECRET = "my-secret-jwt-key-12345";

    /**
     * 脆弱性6: 文字列比較による認証（タイミング攻撃に脆弱）
     */
    @PostMapping("/verify-token")
    public String verifyToken(@RequestParam String token, @RequestParam String expected) {
        // NG: equals()はタイミング攻撃に脆弱
        if (token.equals(expected)) {
            return "Valid";
        }
        return "Invalid";
    }

    /**
     * 安全な乱数生成（参考）
     */
    public String generateSecureToken() {
        // OK: SecureRandom を使用
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return java.util.Base64.getEncoder().encodeToString(bytes);
    }
}

