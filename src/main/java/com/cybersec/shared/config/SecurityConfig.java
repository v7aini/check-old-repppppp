package com.cybersec.shared.config;

import com.cybersec.shared.auth.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;

    @Autowired
    public SecurityConfig(JwtAuthenticationFilter jwtFilter) { this.jwtFilter = jwtFilter; }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF for ALL routes — this platform uses JWT + session
            // CSRF is only needed for cookie-based auth without token, which we don't rely on
            .csrf(c -> c.disable())
            .headers(h -> h.frameOptions(f -> f.sameOrigin()))
            .authorizeHttpRequests(a -> a
                // Public — no auth needed
                .requestMatchers(
                    "/login", "/logout",
                    "/css/**", "/js/**", "/images/**", "/favicon.ico",
                    "/h2-console/**",
                    "/api/public/**",
                    "/api/auth/login",
                    "/ws/**",
                    "/api/ids/threat-summary",
                    "/api/simulation/**",
                    // Swagger UI — open for easy access
                    "/swagger-ui.html", "/swagger-ui/**", "/api-docs/**", "/v3/api-docs/**"
                ).permitAll()
                // REST API — requires auth via JWT Bearer token
                .requestMatchers("/api/ids/**", "/api/tip/**", "/api/network/**",
                                 "/api/investigate/**", "/api/telegram/**")
                    .hasAnyRole("ADMIN", "ANALYST", "VIEWER")
                .requestMatchers("/api/waf/**").hasAnyRole("ADMIN", "ANALYST")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                // All UI pages — requires session login
                .anyRequest().authenticated()
            )
            .formLogin(f -> f
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(l -> l
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
            )
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(12); }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration c) throws Exception {
        return c.getAuthenticationManager();
    }
}
