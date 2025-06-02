package com.zenpals.auth_service_api.config;

import com.zenpals.auth_service_api.security.OAuth2FailureHandler;
import com.zenpals.auth_service_api.security.OAuth2SuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, OAuth2SuccessHandler successHandler,
                                                         OAuth2FailureHandler failureHandler) {
        return http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/auth-service-api/auth/**").permitAll()  // your public endpoints
                        .pathMatchers("/login/oauth2/code/auth0").permitAll()
                        .pathMatchers("/logout").permitAll()
                        .anyExchange().authenticated()
                )
//                We're no longer using spring security's success/failure callback mechanism nor are we using the security context to track the user authentication/authorization
//                .oauth2Login(Customizer.withDefaults()) // <-- this is what enables the /login/oauth2/code/auth0 handler
//                .build();
//                .oauth2Login(oauth2 -> oauth2
//                        .authenticationSuccessHandler(successHandler)
//                        .authenticationFailureHandler(failureHandler)
//                )
//                .logout(logout -> logout.logoutSuccessHandler((exchange, authentication) -> {
//                    // Optional: log or handle logout
//                    return Mono.fromRunnable(() -> System.out.println("🧹 User logged out."));
//                }))
                .build();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*")); // Or specific domains in prod
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true); // Important if you're using cookies

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
}