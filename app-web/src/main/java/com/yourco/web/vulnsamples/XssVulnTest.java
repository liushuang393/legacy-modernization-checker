package com.yourco.web.vulnsamples;

import java.io.IOException;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletResponse;

/**
 * XSS (Cross-Site Scripting) 脆弱性テスト用クラス
 * 
 * 検出対象: Semgrep (p/java)
 * 脆弱性: CWE-79 Cross-site Scripting
 */
@RestController
@RequestMapping("/test/xss")
public class XssVulnTest {

    /**
     * 脆弱性1: 反射型XSS - ユーザー入力をそのまま出力
     * 修正方法: HTMLエスケープを実施、または Content-Type を text/plain に設定
     */
    @GetMapping("/reflect")
    public void reflectXss(
            @RequestParam String message,
            HttpServletResponse response) throws IOException {
        
        response.setContentType("text/html");
        // NG: ユーザー入力をエスケープせずに直接出力
        response.getWriter().write("<html><body>Message: " + message + "</body></html>");
    }

    /**
     * 脆弱性2: 格納型XSS準備 - 危険な文字列をそのまま返却
     * 修正方法: 出力時にエスケープ、または保存時にサニタイズ
     */
    @GetMapping("/stored")
    @ResponseBody
    public String getStoredContent(@RequestParam String id) {
        // 実際にはDBから取得するが、テスト用に直接返却
        String storedContent = "<script>alert('XSS')</script>";
        
        // NG: 格納されたコンテンツをそのまま返却（Content-Typeがtext/htmlの場合危険）
        return "<div>" + storedContent + "</div>";
    }

    /**
     * 安全な実装例（参考）
     */
    @GetMapping("/safe")
    public void safeOutput(
            @RequestParam String message,
            HttpServletResponse response) throws IOException {
        
        // OK: text/plain で出力、またはエスケープ処理
        response.setContentType("text/plain");
        response.getWriter().write("Message: " + message);
    }
}

