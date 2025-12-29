package com.yourco.web.vulnsamples;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A03:2025 - Injection
 * OWASP Top 10:2025 第3位
 *
 * 検出: Semgrep (p/java, p/security-audit)
 */
@RestController
@RequestMapping("/api/a03")
public class A03_Injection {

    private Connection connection;

    /**
     * 脆弱性1: SQL Injection
     */
    @GetMapping("/search")
    public String searchUsers(@RequestParam String name) throws SQLException {
        // NG: 文字列連結によるSQL構築
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(sql).toString();
    }

    /**
     * 脆弱性2: Command Injection
     */
    @GetMapping("/ping")
    public String pingHost(@RequestParam String host) throws IOException {
        // NG: OSコマンドインジェクション
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("ping -c 1 " + host);
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
     * 脆弱性3: ProcessBuilder Command Injection
     */
    @PostMapping("/execute")
    public String executeCommand(@RequestParam String cmd) throws IOException {
        // NG: ProcessBuilder でもインジェクション可能
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
        Process p = pb.start();
        return "Executed: " + cmd;
    }

    /**
     * 脆弱性4: LDAP Injection
     */
    public Object searchLdap(String username, DirContext ctx) throws Exception {
        // NG: LDAPインジェクション
        String filter = "(uid=" + username + ")";
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        return ctx.search("ou=users,dc=example,dc=com", filter, controls);
    }

    /**
     * 脆弱性5: XPath Injection
     */
    public String xpathQuery(String username) {
        // NG: XPathインジェクション
        String xpath = "//users/user[@name='" + username + "']/password";
        return xpath;
    }

    /**
     * 脆弱性6: Expression Language Injection
     */
    @PostMapping("/template")
    public String templateInjection(@RequestBody String template) {
        // NG: ユーザー入力をテンプレートとして評価
        // 実際にはSpEL, OGNL, Freemarkerなどで発生
        return "Template result: " + template.replace("${user}", "admin");
    }

    /**
     * 脆弱性7: Regex DoS (ReDoS)
     */
    @GetMapping("/validate")
    public String validateInput(@RequestParam String input) {
        // NG: 複雑な正規表現によるDoS
        String pattern = "(a+)+$";
        if (input.matches(pattern)) {
            return "Valid";
        }
        return "Invalid";
    }
}

