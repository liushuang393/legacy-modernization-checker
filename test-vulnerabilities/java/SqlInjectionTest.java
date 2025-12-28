package com.yourco.web.test;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.List;
import java.util.Map;

/**
 * SQL Injection 脆弱性テスト用クラス
 * 
 * 検出対象: Semgrep (p/java, カスタムルール)
 * 脆弱性: CWE-89 SQL Injection
 */
@RestController
@RequestMapping("/test/sqli")
public class SqlInjectionTest {

    private final JdbcTemplate jdbcTemplate;
    
    public SqlInjectionTest(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * 脆弱性1: 文字列連結によるSQL Injection
     * 修正方法: PreparedStatement または JdbcTemplate の ? パラメータを使用
     */
    @GetMapping("/users")
    public List<Map<String, Object>> getUsers(@RequestParam String name) {
        // NG: 文字列連結 - SQL Injection 脆弱性
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.queryForList(sql);
    }

    /**
     * 脆弱性2: String.format によるSQL Injection  
     * 修正方法: JdbcTemplate.query(sql, params, mapper) を使用
     */
    @GetMapping("/orders")
    public List<Map<String, Object>> getOrders(@RequestParam String userId) {
        // NG: String.format - SQL Injection 脆弱性
        String sql = String.format("SELECT * FROM orders WHERE user_id = '%s'", userId);
        return jdbcTemplate.queryForList(sql);
    }

    /**
     * 安全な実装例（参考）
     */
    @GetMapping("/safe/users")
    public List<Map<String, Object>> getUsersSafe(@RequestParam String name) {
        // OK: パラメータバインディング
        String sql = "SELECT * FROM users WHERE name = ?";
        return jdbcTemplate.queryForList(sql, name);
    }
}

