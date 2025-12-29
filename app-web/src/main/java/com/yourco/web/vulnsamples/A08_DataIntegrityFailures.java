package com.yourco.web.vulnsamples;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A08:2025 - Software and Data Integrity Failures
 * OWASP Top 10:2025 第8位
 * 
 * 検出: Semgrep (p/java, p/security-audit)
 */
@RestController
@RequestMapping("/api/a08")
public class A08_DataIntegrityFailures {

    /**
     * 脆弱性1: 安全でないデシリアライズ
     * CVE多数の原因となる重大な脆弱性
     */
    @PostMapping("/deserialize")
    public String deserializeObject(@RequestBody byte[] data) {
        try {
            // NG: 信頼できないデータのデシリアライズ
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject();  // 任意のコード実行の可能性
            return "Deserialized: " + obj.getClass().getName();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * 脆弱性2: 署名なしのデータ受け入れ
     */
    @PostMapping("/import")
    public String importData(@RequestBody String jsonData) {
        // NG: データの整合性検証なし
        return "Imported: " + jsonData;
    }

    /**
     * 脆弱性3: 外部からのクラスロード
     */
    @GetMapping("/load-class")
    public String loadClass(@RequestParam String className) {
        try {
            // NG: 任意のクラスをロード可能
            Class<?> clazz = Class.forName(className);
            return "Loaded: " + clazz.getName();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * 脆弱性4: URLからのコードダウンロード実行
     */
    @GetMapping("/download-and-run")
    public String downloadAndRun(@RequestParam String url) {
        try {
            // NG: 外部URLからコードをダウンロードして実行
            java.net.URL scriptUrl = new java.net.URL(url);
            java.io.InputStream is = scriptUrl.openStream();
            // ... 実行コード
            return "Downloaded from: " + url;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * 脆弱性5: 反射によるオブジェクト生成
     */
    @GetMapping("/reflect")
    public String reflectCreate(@RequestParam String className, @RequestParam String method) {
        try {
            // NG: 任意のクラスのメソッドを実行可能
            Class<?> clazz = Class.forName(className);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            java.lang.reflect.Method m = clazz.getMethod(method);
            return "Result: " + m.invoke(instance);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

