package com.yourco.web.vulnsamples;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A09:2025 - Security Logging and Monitoring Failures
 * OWASP Top 10:2025 第9位
 * 
 * 検出: Semgrep (カスタムルール)
 */
@RestController
@RequestMapping("/api/a09")
public class A09_LoggingFailures {

    private static final Logger logger = LoggerFactory.getLogger(A09_LoggingFailures.class);

    /**
     * 脆弱性1: 機密情報のログ出力
     */
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // NG: パスワードをログに出力
        logger.info("Login attempt - username: {}, password: {}", username, password);
        System.out.println("User " + username + " password: " + password);
        return "Login processed";
    }

    /**
     * 脆弱性2: クレジットカード情報のログ出力
     */
    @PostMapping("/payment")
    public String processPayment(
            @RequestParam String cardNumber,
            @RequestParam String cvv) {
        // NG: カード情報をログに出力
        logger.debug("Processing payment for card: {} cvv: {}", cardNumber, cvv);
        return "Payment processed";
    }

    /**
     * 脆弱性3: トークン/APIキーのログ出力
     */
    @GetMapping("/api-call")
    public String callExternalApi(@RequestHeader("Authorization") String token) {
        // NG: 認証トークンをログに出力
        logger.info("API call with token: {}", token);
        return "API called";
    }

    /**
     * 脆弱性4: ログインジェクション
     */
    @GetMapping("/search")
    public String search(@RequestParam String query) {
        // NG: ユーザー入力を直接ログに出力（ログインジェクション）
        logger.info("Search query: " + query);  // \n などで偽ログ行を挿入可能
        return "Search results for: " + query;
    }

    /**
     * 脆弱性5: 例外の詳細ログ出力
     */
    @GetMapping("/process")
    public String process(@RequestParam String data) {
        try {
            // 何か処理
            throw new RuntimeException("Database connection failed: jdbc:mysql://dbserver:3306/prod?user=admin&password=secret123");
        } catch (Exception e) {
            // NG: 接続文字列など機密情報を含む例外をログ出力
            logger.error("Error occurred", e);
            return "Error: " + e.getMessage();
        }
    }
}

