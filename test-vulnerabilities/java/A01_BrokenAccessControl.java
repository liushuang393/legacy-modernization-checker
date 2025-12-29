package com.yourco.web.vulnsamples;

import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;
import java.io.*;

/**
 * A01:2025 - Broken Access Control
 * OWASP Top 10:2025 第1位
 * 
 * 検出: Semgrep (p/java, p/security-audit)
 */
@RestController
@RequestMapping("/api/a01")
public class A01_BrokenAccessControl {

    /**
     * 脆弱性1: IDOR (Insecure Direct Object Reference)
     * ユーザーIDを直接パラメータで受け取り、認可チェックなし
     */
    @GetMapping("/users/{userId}/profile")
    public String getUserProfile(@PathVariable String userId) {
        // NG: 認可チェックなしで任意のユーザー情報にアクセス可能
        return "User profile for: " + userId;
    }

    /**
     * 脆弱性2: Path Traversal
     */
    @GetMapping("/files")
    public String readFile(@RequestParam String filename) throws IOException {
        // NG: パス検証なしでファイル読み取り
        File file = new File("/data/uploads/" + filename);
        return new String(java.nio.file.Files.readAllBytes(file.toPath()));
    }

    /**
     * 脆弱性3: 認可バイパス - ロールチェック欠如
     */
    @DeleteMapping("/admin/users/{userId}")
    public String deleteUser(@PathVariable String userId) {
        // NG: 管理者権限チェックなし
        return "Deleted user: " + userId;
    }
}

