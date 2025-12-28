package com.yourco.web.test;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;

/**
 * Path Traversal 脆弱性テスト用クラス
 * 
 * 検出対象: Semgrep (p/java, カスタムルール)
 * 脆弱性: CWE-22 Path Traversal
 */
@RestController
@RequestMapping("/test/path")
public class PathTraversalTest {

    private static final String BASE_DIR = "/app/uploads";

    /**
     * 脆弱性1: ファイル読み取りでのPath Traversal
     * 攻撃例: filename=../../../etc/passwd
     * 修正方法: ファイル名の検証、正規化後のパス検証
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadFile(@RequestParam String filename) throws Exception {
        // NG: ユーザー入力をそのままパスに使用
        Path filePath = Paths.get(BASE_DIR, filename);
        Resource resource = new UrlResource(filePath.toUri());
        
        return ResponseEntity.ok().body(resource);
    }

    /**
     * 脆弱性2: ファイル書き込みでのPath Traversal
     * 攻撃例: filename=../../../tmp/malicious.sh
     * 修正方法: 許可されたディレクトリ内かを検証
     */
    @PostMapping("/upload")
    public String uploadFile(
            @RequestParam String filename,
            @RequestBody byte[] content) throws IOException {
        
        // NG: 検証なしでファイルパスを構築
        File file = new File(BASE_DIR + "/" + filename);
        Files.write(file.toPath(), content);
        
        return "Uploaded: " + filename;
    }

    /**
     * 安全な実装例（参考）
     */
    @GetMapping("/safe/download")
    public ResponseEntity<Resource> downloadFileSafe(@RequestParam String filename) throws Exception {
        // OK: パスの正規化と検証
        Path basePath = Paths.get(BASE_DIR).toAbsolutePath().normalize();
        Path filePath = basePath.resolve(filename).normalize();
        
        // ベースディレクトリ外へのアクセスを防止
        if (!filePath.startsWith(basePath)) {
            throw new SecurityException("Invalid file path");
        }
        
        Resource resource = new UrlResource(filePath.toUri());
        return ResponseEntity.ok().body(resource);
    }
}

