package com.yourco.web.vulnsamples;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A10:2025 - Server-Side Request Forgery (SSRF)
 * OWASP Top 10:2025 第10位
 * 
 * 検出: Semgrep (p/java, p/security-audit)
 */
@RestController
@RequestMapping("/api/a10")
public class A10_SSRF {

    /**
     * 脆弱性1: 基本的なSSRF
     */
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam String url) throws IOException {
        // NG: ユーザー指定URLへのリクエスト
        URL target = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        return response.toString();
    }

    /**
     * 脆弱性2: 内部サービスへのSSRF
     */
    @GetMapping("/proxy")
    public String proxyRequest(
            @RequestParam String host,
            @RequestParam String path) throws IOException {
        // NG: 内部ネットワークへのアクセス可能
        String url = "http://" + host + path;
        URL target = new URL(url);
        return new BufferedReader(
            new InputStreamReader(target.openStream()))
            .lines()
            .collect(java.util.stream.Collectors.joining());
    }

    /**
     * 脆弱性3: URLConnectionを使ったSSRF
     */
    @PostMapping("/webhook")
    public String sendWebhook(@RequestParam String webhookUrl, @RequestBody String payload) 
            throws IOException {
        // NG: 任意のURLへPOSTリクエスト
        URL url = new URL(webhookUrl);
        URLConnection conn = url.openConnection();
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.getBytes());
        }
        return "Webhook sent";
    }

    /**
     * 脆弱性4: ファイルプロトコルを含むSSRF
     */
    @GetMapping("/read")
    public String readResource(@RequestParam String resource) throws IOException {
        // NG: file:// プロトコルでローカルファイル読み取り可能
        URL url = new URL(resource);  // file:///etc/passwd など
        return new BufferedReader(
            new InputStreamReader(url.openStream()))
            .lines()
            .collect(java.util.stream.Collectors.joining("\n"));
    }

    /**
     * 脆弱性5: HttpClient SSRF
     */
    @GetMapping("/api-proxy")
    public String apiProxy(@RequestParam String apiUrl) throws IOException {
        // NG: 任意のURLへHTTPリクエスト
        URL url = new URL(apiUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        return reader.lines().collect(java.util.stream.Collectors.joining());
    }
}

