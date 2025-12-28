package com.yourco.web.test;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

/**
 * Insecure Deserialization 脆弱性テスト用クラス
 * 
 * 検出対象: Semgrep (p/java, カスタムルール)
 * 脆弱性: CWE-502 Deserialization of Untrusted Data
 */
@RestController
@RequestMapping("/test/deserialize")
public class DeserializationTest {

    /**
     * 脆弱性1: 信頼されていないデータのデシリアライズ
     * 攻撃例: 悪意のあるシリアライズデータでRCE
     * 修正方法: ObjectInputFilter を使用、または JSON など安全な形式を使用
     */
    @PostMapping("/object")
    public String deserializeObject(@RequestBody String base64Data) throws Exception {
        byte[] data = Base64.getDecoder().decode(base64Data);
        
        // NG: 信頼されていないデータを直接デシリアライズ
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        ois.close();
        
        return "Deserialized: " + obj.getClass().getName();
    }

    /**
     * 脆弱性2: ファイルからの危険なデシリアライズ
     * 修正方法: ファイル内容の検証、またはJSON形式を使用
     */
    @PostMapping("/file")
    public String deserializeFromFile(@RequestParam String filePath) throws Exception {
        // NG: ファイルから直接デシリアライズ（Path Traversalも含む）
        FileInputStream fis = new FileInputStream(filePath);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object obj = ois.readObject();
        ois.close();
        fis.close();
        
        return "Loaded object: " + obj.toString();
    }

    /**
     * 安全な実装例（参考）- ObjectInputFilter 使用
     */
    @PostMapping("/safe")
    public String deserializeSafe(@RequestBody String base64Data) throws Exception {
        byte[] data = Base64.getDecoder().decode(base64Data);
        
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        
        // OK: ObjectInputFilter で許可するクラスを制限
        ois.setObjectInputFilter(filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            if (clazz != null) {
                // 許可リストに含まれるクラスのみ許可
                if (clazz.getName().startsWith("com.yourco.web.dto.")) {
                    return ObjectInputFilter.Status.ALLOWED;
                }
                return ObjectInputFilter.Status.REJECTED;
            }
            return ObjectInputFilter.Status.UNDECIDED;
        });
        
        Object obj = ois.readObject();
        ois.close();
        
        return "Safely deserialized: " + obj.getClass().getName();
    }
}

