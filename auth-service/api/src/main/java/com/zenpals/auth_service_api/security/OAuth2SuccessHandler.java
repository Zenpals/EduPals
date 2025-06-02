package com.zenpals.auth_service_api.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Slf4j
@Component
public class OAuth2SuccessHandler implements ServerAuthenticationSuccessHandler {

    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

    public OAuth2SuccessHandler(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        ServerWebExchange exchange = webFilterExchange.getExchange();

        log.info("✅ User successfully authenticated: {}", authentication.getName());

        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            log.warn("Authentication is not OAuth2AuthenticationToken");
            return webFilterExchange.getChain().filter(exchange);
        }

        String registrationId = oauthToken.getAuthorizedClientRegistrationId();
        String principalName = oauthToken.getName();

        // Load the authorized client to get access token
        return authorizedClientService.loadAuthorizedClient(registrationId, principalName)
                .flatMap(authClient -> {
                    if (authClient != null && authClient.getAccessToken() != null) {
                        String accessToken = authClient.getAccessToken().getTokenValue();
                        log.info("Access token for user [{}]: {}", principalName, accessToken);

                        // Create a secure, HTTP-only cookie with access token
                        ResponseCookie cookie = ResponseCookie.from("access_token", accessToken)
                                .httpOnly(true)
                                .secure(true)
                                .path("/")
                                .maxAge(Duration.ofHours(1))
                                .build();

                        exchange.getResponse().addCookie(cookie);

                        // Continue the filter chain (default redirect or response)
                        return webFilterExchange.getChain().filter(exchange);
                    } else {
                        log.warn("No access token found for user [{}]", principalName);
                        return webFilterExchange.getChain().filter(exchange);
                    }
                });
    }
}
