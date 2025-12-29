package com.yourco.web.vulnerable;

import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import java.io.*;
import java.nio.file.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 脆弱なファイル処理（テスト用）
 * ファイル操作に関する脆弱性サンプル
 */
@Component
public class InsecureFileHandler {

    // [VULN-019] 安全でないファイルアップロード - Semgrep検出対象
    public String uploadFile(MultipartFile file, String uploadDir) throws IOException {
        // 危険：ファイル名の検証なし、拡張子チェックなし
        String filename = file.getOriginalFilename();
        Path targetPath = Paths.get(uploadDir, filename);
        Files.copy(file.getInputStream(), targetPath);
        return targetPath.toString();
    }

    // [VULN-020] Zip Slip脆弱性 - Semgrep/Trivy検出対象
    public void extractZip(String zipPath, String destDir) throws IOException {
        // 危険：ZipEntryのパスを検証せずに展開
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipPath))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // 危険：../を含むパスでディレクトリトラバーサル可能
                File destFile = new File(destDir, entry.getName());
                if (entry.isDirectory()) {
                    destFile.mkdirs();
                } else {
                    try (FileOutputStream fos = new FileOutputStream(destFile)) {
                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
            }
        }
    }

    // [VULN-021] 一時ファイルの安全でない作成 - Semgrep検出対象
    public File createTempFile(String content) throws IOException {
        // 危険：予測可能なファイル名
        File tempFile = new File("/tmp/app_temp_" + System.currentTimeMillis() + ".txt");
        try (FileWriter writer = new FileWriter(tempFile)) {
            writer.write(content);
        }
        return tempFile;
    }

    // [VULN-022] シンボリックリンク攻撃に脆弱 - Semgrep検出対象
    public void writeToFile(String path, String content) throws IOException {
        // 危険：シンボリックリンクのチェックなし
        try (FileWriter writer = new FileWriter(path)) {
            writer.write(content);
        }
    }

    // [VULN-023] 安全でないデシリアライズ - Semgrep検出対象
    public Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        // 危険：信頼できないデータのデシリアライズ
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    // [VULN-024] ファイルパーミッションの設定なし - Semgrep検出対象
    public void createSensitiveFile(String path, String sensitiveData) throws IOException {
        // 危険：適切なパーミッション設定なし
        Files.write(Paths.get(path), sensitiveData.getBytes());
        // 本来は Files.setPosixFilePermissions() で制限すべき
    }
}

