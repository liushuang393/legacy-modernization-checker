package com.yourco.web.vulnsamples;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Command Injection 脆弱性テスト用クラス
 * 
 * 検出対象: Semgrep (p/java, カスタムルール)
 * 脆弱性: CWE-78 OS Command Injection
 */
@RestController
@RequestMapping("/test/cmd")
public class CommandInjectionTest {

    /**
     * 脆弱性1: Runtime.exec() でのコマンドインジェクション
     * 攻撃例: host=localhost;rm -rf /
     * 修正方法: ユーザー入力をコマンドに含めない、またはホワイトリスト検証
     */
    @GetMapping("/ping")
    public String pingHost(@RequestParam String host) throws Exception {
        // NG: ユーザー入力をそのままコマンドに使用
        Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    /**
     * 脆弱性2: ProcessBuilder でのコマンドインジェクション
     * 修正方法: 引数を配列で分離、シェル経由の実行を避ける
     */
    @PostMapping("/execute")
    public String executeCommand(@RequestParam String command) throws Exception {
        // NG: シェル経由でユーザーコマンドを実行
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    /**
     * 安全な実装例（参考）
     */
    @GetMapping("/safe/ping")
    public String pingHostSafe(@RequestParam String host) throws Exception {
        // OK: ホワイトリスト検証 + 引数分離
        if (!host.matches("^[a-zA-Z0-9.-]+$")) {
            throw new IllegalArgumentException("Invalid host format");
        }
        
        // 引数を配列で分離（シェル解釈を回避）
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }
}

