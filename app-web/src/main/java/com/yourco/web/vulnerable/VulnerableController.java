package com.yourco.web.vulnerable;

import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Random;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;

/**
 * 脆弱性テスト用コントローラー（本番使用禁止）
 * 各種セキュリティスキャンツールの検証用サンプルコード
 */
@RestController
@RequestMapping("/api/vulnerable")
public class VulnerableController {

    private final JdbcTemplate jdbcTemplate;

    // [VULN-001] ハードコードされた認証情報 - Gitleaks/Semgrep検出対象
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String API_KEY = "sk-proj-abcdef123456789";
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    public VulnerableController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // [VULN-002] SQLインジェクション - Semgrep検出対象
    @GetMapping("/users")
    public String getUserByName(@RequestParam String name) {
        // 危険：ユーザー入力を直接SQLに結合
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.queryForList(sql).toString();
    }

    // [VULN-003] コマンドインジェクション - Semgrep検出対象
    @PostMapping("/execute")
    public String executeCommand(@RequestParam String cmd) throws IOException {
        // 危険：ユーザー入力をシェルコマンドとして実行
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("sh -c " + cmd);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        return reader.readLine();
    }

    // [VULN-004] パストラバーサル - Semgrep検出対象
    @GetMapping("/file")
    public String readFile(@RequestParam String filename) throws IOException {
        // 危険：ユーザー入力をファイルパスに直接使用
        File file = new File("/data/" + filename);
        return new String(java.nio.file.Files.readAllBytes(file.toPath()));
    }

    // [VULN-005] XSS（反射型） - Semgrep検出対象
    @GetMapping("/greet")
    public void greet(@RequestParam String name, HttpServletResponse response) throws IOException {
        // 危険：ユーザー入力をエスケープせずにHTMLに出力
        response.setContentType("text/html");
        response.getWriter().write("<html><body>Hello, " + name + "</body></html>");
    }

    // [VULN-006] SSRF（Server-Side Request Forgery） - Semgrep検出対象
    @GetMapping("/fetch")
    public String fetchUrl(@RequestParam String url) throws IOException {
        // 危険：ユーザー指定のURLにサーバーからアクセス
        URL targetUrl = new URL(url);
        BufferedReader reader = new BufferedReader(new InputStreamReader(targetUrl.openStream()));
        return reader.readLine();
    }

    // [VULN-007] 安全でない暗号化（MD5） - Semgrep検出対象
    @PostMapping("/hash")
    public String hashPassword(@RequestParam String password) throws Exception {
        // 危険：MD5は暗号学的に安全ではない
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        return bytesToHex(digest);
    }

    // [VULN-008] 安全でない乱数生成 - Semgrep検出対象
    @GetMapping("/token")
    public String generateToken() {
        // 危険：java.util.Randomはセキュリティ用途に不適切
        Random random = new Random();
        return String.valueOf(random.nextLong());
    }

    // [VULN-009] XXE（XML External Entity） - Semgrep検出対象
    @PostMapping("/parse-xml")
    public String parseXml(@RequestBody String xmlContent) throws Exception {
        // 危険：外部エンティティ参照が有効なXMLパーサー
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // XXE対策なし
        factory.newDocumentBuilder().parse(new InputSource(new StringReader(xmlContent)));
        return "Parsed";
    }

    // [VULN-010] オープンリダイレクト - Semgrep検出対象
    @GetMapping("/redirect")
    public void redirect(@RequestParam String url, HttpServletResponse response) throws IOException {
        // 危険：ユーザー指定のURLにリダイレクト
        response.sendRedirect(url);
    }

    // [VULN-011] ログインジェクション - Semgrep検出対象
    @PostMapping("/login")
    public String login(@RequestParam String username, HttpServletRequest request) {
        // 危険：ユーザー入力をそのままログに出力
        System.out.println("Login attempt: " + username + " from " + request.getRemoteAddr());
        return "OK";
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

