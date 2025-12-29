package com.yourco.web.vulnsamples;

import org.springframework.web.bind.annotation.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.io.StringReader;

/**
 * A05:2025 - Security Misconfiguration
 * OWASP Top 10:2025 第5位
 * 
 * 検出: Semgrep (p/java, p/security-audit)
 */
@RestController
@RequestMapping("/api/a05")
public class A05_SecurityMisconfiguration {

    /**
     * 脆弱性1: XXE (XML External Entity) - DTD有効
     */
    @PostMapping("/parse-xml")
    public String parseXml(@RequestBody String xml) throws Exception {
        // NG: XXE脆弱性 - 外部エンティティが有効
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // 以下の設定がないためXXE脆弱
        // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new InputSource(new StringReader(xml)));
        return "XML parsed";
    }

    /**
     * 脆弱性2: デバッグ情報の漏洩
     */
    @GetMapping("/debug")
    public String debugInfo() {
        // NG: システム情報の漏洩
        StringBuilder sb = new StringBuilder();
        sb.append("Java Version: ").append(System.getProperty("java.version")).append("\n");
        sb.append("OS: ").append(System.getProperty("os.name")).append("\n");
        sb.append("User: ").append(System.getProperty("user.name")).append("\n");
        sb.append("Home: ").append(System.getProperty("user.home")).append("\n");
        return sb.toString();
    }

    /**
     * 脆弱性3: スタックトレースの漏洩
     */
    @GetMapping("/error")
    public String triggerError() {
        try {
            throw new RuntimeException("Internal error");
        } catch (Exception e) {
            // NG: スタックトレースを直接返却
            java.io.StringWriter sw = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            return sw.toString();
        }
    }

    /**
     * 脆弱性4: 詳細なエラーメッセージ
     */
    @GetMapping("/user/{id}")
    public String getUser(@PathVariable String id) {
        // NG: 詳細すぎるエラーメッセージ
        return "User not found in table 'users' with primary key 'id' = " + id;
    }
}

/**
 * 脆弱性5: CORS設定ミス
 */
@Configuration
class CorsConfig {
    @Bean
    public org.springframework.web.servlet.config.annotation.WebMvcConfigurer corsConfigurer() {
        return new org.springframework.web.servlet.config.annotation.WebMvcConfigurer() {
            @Override
            public void addCorsMappings(org.springframework.web.servlet.config.annotation.CorsRegistry registry) {
                // NG: すべてのオリジンを許可
                registry.addMapping("/**")
                    .allowedOrigins("*")
                    .allowedMethods("*");
            }
        };
    }
}

