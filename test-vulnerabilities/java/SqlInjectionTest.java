package com.yourco.web.vulnsamples;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * SQL Injection 脆弱性テスト用クラス
 *
 * 検出対象: Semgrep (p/java, カスタムルール)
 * 脆弱性: CWE-89 SQL Injection
 */
@RestController
@RequestMapping("/test/sqli")
public class SqlInjectionTest {

    private Connection connection;

    /**
     * 脆弱性1: 文字列連結によるSQL Injection
     * 修正方法: PreparedStatement を使用
     */
    @GetMapping("/users")
    public String getUsers(@RequestParam String name) throws SQLException {
        // NG: 文字列連結 - SQL Injection 脆弱性
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        return rs.toString();
    }

    /**
     * 脆弱性2: String.format によるSQL Injection
     * 修正方法: PreparedStatement を使用
     */
    @GetMapping("/orders")
    public String getOrders(@RequestParam String userId) throws SQLException {
        // NG: String.format - SQL Injection 脆弱性
        String sql = String.format("SELECT * FROM orders WHERE user_id = '%s'", userId);
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        return rs.toString();
    }

    /**
     * 安全な実装例（参考）
     */
    @GetMapping("/safe/users")
    public String getUsersSafe(@RequestParam String name) throws SQLException {
        // OK: パラメータバインディング (PreparedStatement)
        String sql = "SELECT * FROM users WHERE name = ?";
        PreparedStatement pstmt = connection.prepareStatement(sql);
        pstmt.setString(1, name);
        ResultSet rs = pstmt.executeQuery();
        return rs.toString();
    }
}

