package com.yourco.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * セキュリティ基線（Baseline）
 * - 既定は「拒否（deny）」、必要なものだけ明示的に許可します。
 * - CSRF は原則有効（安易に disable しない）。
 *
 * 注意：
 * - 実案件では OIDC/JWT などに置き換えることを推奨します。
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityBaselineConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.withDefaults())
        .authorizeHttpRequests(auth -> auth
            // Health check: 公開する場合も、IP 制限などの追加対策を推奨
            .requestMatchers("/actuator/health").permitAll()
            // それ以外の Actuator は運用者のみ
            .requestMatchers("/actuator/**").hasRole("OPS")
            // API は認証必須（役割は案件に合わせて細分化）
            .requestMatchers("/api/**").authenticated()
            // 既定拒否
            .anyRequest().denyAll()
        )
        .httpBasic(Customizer.withDefaults());

    return http.build();
  }
}
