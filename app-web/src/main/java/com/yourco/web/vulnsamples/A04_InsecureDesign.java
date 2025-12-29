package com.yourco.web.vulnsamples;

import org.springframework.web.bind.annotation.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * A04:2025 - Insecure Design
 * OWASP Top 10:2025 第4位
 * 
 * 検出: Semgrep カスタムルール
 */
@RestController
@RequestMapping("/api/a04")
public class A04_InsecureDesign {

    private Map<String, Integer> loginAttempts = new ConcurrentHashMap<>();

    /**
     * 脆弱性1: レート制限なし - ブルートフォース可能
     */
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // NG: ログイン試行回数の制限なし
        if (authenticate(username, password)) {
            return "Login successful";
        }
        return "Login failed";
    }

    /**
     * 脆弱性2: 予測可能なリセットトークン
     */
    @PostMapping("/password-reset")
    public String resetPassword(@RequestParam String email) {
        // NG: 予測可能なトークン生成
        String token = String.valueOf(System.currentTimeMillis());
        return "Reset token: " + token;
    }

    /**
     * 脆弱性3: 機密情報をURLパラメータで送信
     */
    @GetMapping("/verify")
    public String verifyAccount(
            @RequestParam String email,
            @RequestParam String token,
            @RequestParam String password) {  // NG: パスワードがGETパラメータ
        return "Account verified";
    }

    /**
     * 脆弱性4: セッション固定攻撃に脆弱
     */
    @PostMapping("/auth")
    public String authenticate(@RequestParam String sessionId) {
        // NG: ユーザー提供のセッションIDをそのまま使用
        return "Authenticated with session: " + sessionId;
    }

    private boolean authenticate(String username, String password) {
        return "admin".equals(username) && "password".equals(password);
    }
}

