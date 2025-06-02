package com.zenpals.auth_service_api.WebFilters;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class OAuth2CallbackLoggingFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if ("/login/oauth2/code/auth0".equals(path)) {
            log.info("➡️ OAuth2 login callback hit: {}", exchange.getRequest().getURI());
        }

        return chain.filter(exchange);
    }
}

