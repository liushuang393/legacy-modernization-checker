package com.yourco.web.vulnsamples;

/**
 * A06:2025 - Vulnerable and Outdated Components
 * OWASP Top 10:2025 第6位
 * 
 * 検出: OWASP Dependency-Check, Trivy
 * 
 * このファイル自体ではなく、pom.xml に古い依存関係を追加することで検出
 * テスト用に以下の脆弱な依存関係を test-vulnerabilities/pom-vulnerable.xml に定義
 */
public class A06_VulnerableComponents {

    /**
     * 脆弱なライブラリ使用例（コメント）
     * 
     * <!-- Log4j 2.14.1 - CVE-2021-44228 (Log4Shell) CRITICAL -->
     * <dependency>
     *     <groupId>org.apache.logging.log4j</groupId>
     *     <artifactId>log4j-core</artifactId>
     *     <version>2.14.1</version>
     * </dependency>
     * 
     * <!-- Spring Framework 5.2.0 - 複数のCVE -->
     * <dependency>
     *     <groupId>org.springframework</groupId>
     *     <artifactId>spring-core</artifactId>
     *     <version>5.2.0.RELEASE</version>
     * </dependency>
     * 
     * <!-- Jackson 2.9.8 - CVE-2019-12384 など -->
     * <dependency>
     *     <groupId>com.fasterxml.jackson.core</groupId>
     *     <artifactId>jackson-databind</artifactId>
     *     <version>2.9.8</version>
     * </dependency>
     * 
     * <!-- Commons Collections 3.2.1 - デシリアライズ脆弱性 -->
     * <dependency>
     *     <groupId>commons-collections</groupId>
     *     <artifactId>commons-collections</artifactId>
     *     <version>3.2.1</version>
     * </dependency>
     */
    
    public static void main(String[] args) {
        System.out.println("Vulnerable components test - check pom.xml for CVEs");
    }
}

