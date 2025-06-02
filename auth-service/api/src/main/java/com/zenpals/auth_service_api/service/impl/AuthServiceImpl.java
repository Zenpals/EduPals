package com.zenpals.auth_service_api.service.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zenpals.auth_service_api.domain.documents.RefreshTokenDocument;
import com.zenpals.auth_service_api.repository.RefreshTokenRepository;
import com.zenpals.auth_service_api.request.ApiLogoutRequest;
import com.zenpals.auth_service_api.request.ApiRefreshTokenRequest;
import com.zenpals.auth_service_api.request.ApiUserInfoRequest;
import com.zenpals.auth_service_api.request.models.UserInfo;
import com.zenpals.auth_service_api.response.*;
import com.zenpals.auth_service_api.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private final WebClient webClient;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private final ObjectMapper objectMapper;
    @Value("${auth0.domain}")
    private String domain;
    @Value("${spring.security.oauth2.client.registration.auth0.client-id}")
    private String clientId;
    @Value("${spring.security.oauth2.client.registration.auth0.client-secret}")
    private String clientSecret;
    @Value("${spring.security.oauth2.client.provider.auth0.token-uri}")
    private String auth0TokenUri;

    @Value("${spring.security.oauth2.client.registration.auth0.redirect-uri}")
    private String redirectUri;

    @Value("${spring.security.oauth2.client.registration.auth0.scopes}")
    private List<String> scopes;

    public AuthServiceImpl(WebClient.Builder webClientBuilder,ObjectMapper objectMapper) {
        this.webClient = webClientBuilder.baseUrl("https://dev-zenpals.us.auth0.com").build(); // Auth0 base URL
        this.objectMapper = objectMapper;
    }

    @Override
     public Mono<ApiAuthorizeResponse> authorize(){
        try {
            String scopesWithSpaces = String.join(" ", scopes);
            String urlEncodedScopes = scopesWithSpaces.replace(" ", "%20");
            // Constructing the authorization URL
            String authUrl = UriComponentsBuilder
                    .fromHttpUrl("https://" + domain + "/authorize")
                    .queryParam("response_type", "code")
                    .queryParam("client_id", clientId)
                    .queryParam("redirect_uri", redirectUri)
                    .queryParam("audience", "zenpals-auth-service-management-api")
                    .queryParam("scope",urlEncodedScopes)
                    .build()
                    .toUriString();

            ApiAuthorizeResponse apiAuthorizeResponse = new ApiAuthorizeResponse();
            apiAuthorizeResponse.setRedirectUri(authUrl);
            apiAuthorizeResponse.setError(null);
            apiAuthorizeResponse.setErrorMessage(null);

            logger.info("The ApiAuthorizeResponse  is as follows :: {}", apiAuthorizeResponse);
            return Mono.just(apiAuthorizeResponse);
        } catch (Exception e) {
            // Log the exception for debugging
            logger.error("Error occurred while constructing authorization URL: {}", e.getMessage(), e);

            // Return a custom error response
            ApiAuthorizeResponse errorResponse = new ApiAuthorizeResponse();
            errorResponse.setError("50000");
            errorResponse.setErrorMessage("An error occurred while constructing the authorization URL.");

            // You can also send a more detailed message depending on the exception type if needed
            return Mono.just(errorResponse);
        }
    }

    @Override
    public Mono<ApiAuthTokenResponse> exchangeCodeForToken(String code){
        String scopesWithSpaces = String.join(" ", scopes);
        String urlEncodedScopes = scopesWithSpaces.replace(" ", "%20");
        var body = new LinkedMultiValueMap<String, String>();
        body.add("grant_type", "authorization_code");
        body.add("audience","zenpals-auth-service-management-api");
        body.add("code", code);
        body.add("redirect_uri", redirectUri);
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("scope",urlEncodedScopes);

        return webClient.post()
                .uri(auth0TokenUri)
                .bodyValue(body)
                .retrieve()
                .onStatus(status -> status.is4xxClientError(), response -> {
                    return response.bodyToMono(String.class)
                            .flatMap(errorBody -> {
                                logger.error("4xx error occurred: {}", errorBody);
                                return Mono.error(new RuntimeException("Client error occurred: " + errorBody));
                            });
                })
                .onStatus(status -> status.is5xxServerError(), response -> {
                    return response.bodyToMono(String.class)
                            .flatMap(errorBody -> {
                                logger.error("5xx error occurred: {}", errorBody);
                                return Mono.error(new RuntimeException("Server error occurred: " + errorBody));
                            });
                })
                .bodyToMono(String.class)
                .doOnSuccess(responseBody -> {
                    logger.info("Raw response body: {}", responseBody);
                })
                .flatMap(responseBody -> {
                    try {
                        ApiAuthTokenResponse apiAuthTokenResponse = objectMapper.readValue(responseBody, ApiAuthTokenResponse.class);
                        return Mono.just(apiAuthTokenResponse);
                    } catch (Exception e) {
                        logger.error("Error parsing response body to ApiAuthTokenResponse", e);
                        return Mono.error(new RuntimeException("Error parsing response body"));
                    }
                })
                .flatMap(tokenResponse -> {
                    try {
                        DecodedJWT decodedIdToken = JWT.decode(tokenResponse.getId_token());
                        String userId = decodedIdToken.getSubject();

                        if (userId == null || userId.isEmpty()) {
                            logger.warn("User ID (sub) claim not found in ID token");
                            return Mono.just(tokenResponse); // continue without saving token
                        }

                        String newRefreshToken = tokenResponse.getRefresh_token();
                        tokenResponse.setRefresh_token(null);
                        if (newRefreshToken != null && !newRefreshToken.isEmpty()) {
                            // Fetch existing document or create new one
                            return refreshTokenRepository.findById(userId)
                                    .defaultIfEmpty(new RefreshTokenDocument())
                                    .flatMap(existingDoc -> {
                                        boolean isNewToken = !newRefreshToken.equals(existingDoc.getRefreshToken());
                                        if (isNewToken) {
                                            existingDoc.setId(userId);
                                            existingDoc.setRefreshToken(newRefreshToken);
                                            existingDoc.setExpiresAt(Date.from(Instant.now().plusSeconds(2592000)));
                                            logger.info("Saving new refresh token for userId: {}", userId);
                                            return refreshTokenRepository.save(existingDoc)
                                                    .doOnSuccess(saved -> logger.info("Saved refresh token for userId: {}", userId))
                                                    .thenReturn(tokenResponse);
                                        } else {
                                            logger.info("Refresh token unchanged for userId: {}, skipping save.", userId);
                                            return Mono.just(tokenResponse);
                                        }
                                    });
                        } else {
                            logger.info("No new refresh token returned for userId: {}, skipping save.", userId);
                            return Mono.just(tokenResponse);
                        }
                    }  catch (Exception e) {
                        logger.error("Error decoding ID token or saving refresh token", e);
                        // Return tokenResponse anyway; we'll not  fail entire flow due to this error This niharika will handle or i'll depends maybe we try saving the refreshtoken later in a new attempt.
                        return Mono.just(tokenResponse);
                    }
                })
                .doOnSuccess(response -> logger.info("Successfully received token response: {}", response))
                .onErrorResume(WebClientResponseException.class, e -> {
                    logger.error("WebClient error: {}", e.getMessage());
                    ApiAuthTokenResponse errorResponse = new ApiAuthTokenResponse();
                    errorResponse.setErrorCode("WEBCLIENT_ERROR");
                    errorResponse.setErrorMessage(e.getMessage());
                    return Mono.just(errorResponse);
                })
                .onErrorResume(RuntimeException.class, e -> {
                    logger.error("Error during token exchange: {}", e.getMessage());
                    ApiAuthTokenResponse errorResponse = new ApiAuthTokenResponse();
                    errorResponse.setErrorCode("RUNTIME_ERROR");
                    errorResponse.setErrorMessage(e.getMessage());
                    return Mono.just(errorResponse);
                });

    }

    @Override
    public Mono<ApiRefreshTokenResponse> refreshToken(Mono<ApiRefreshTokenRequest> requestMono){
        return requestMono
                .flatMap(request -> {
                    // Validate input
                    if (request.getIdentifier() == null || request.getIdentifier().isEmpty()) {
                        ApiRefreshTokenResponse errorResponse = new ApiRefreshTokenResponse();
                        errorResponse.setErrorCode("MISSING_IDENTIFIER");
                        errorResponse.setErrorMessage("Identifier must be provided.");
                        errorResponse.setSuccess(false);
                        return Mono.just(errorResponse);
                    }

                    // Find refresh token doc in DB
                    return refreshTokenRepository.findById(request.getIdentifier())
                            .flatMap(refreshTokenDocument -> {
                                String storedRefreshToken = refreshTokenDocument.getRefreshToken();

                                var body = new LinkedMultiValueMap<String, String>();
                                body.add("grant_type", "refresh_token");
                                body.add("client_id", clientId);
                                body.add("client_secret", clientSecret);
                                body.add("refresh_token", storedRefreshToken);

                                // Call Auth0 token endpoint
                                return webClient.post()
                                        .uri(auth0TokenUri)
                                        .bodyValue(body)
                                        .retrieve()
                                        .onStatus(status -> status.is4xxClientError() || status.is5xxServerError(), response ->
                                                response.bodyToMono(String.class).flatMap(errorBody -> {
                                                    logger.error("Error refreshing token from Auth0: {}", errorBody);

                                                    if (errorBody.contains("invalid_grant")) {
                                                        // Invalid refresh token: we'll delete this record from the DB, then raise an error
                                                        return refreshTokenRepository.delete(refreshTokenDocument)
                                                                .then(Mono.error(new RuntimeException("Invalid refresh token at Auth0. Token removed from DB.")));
                                                    } else {
                                                        return Mono.error(new RuntimeException("Auth0 error during refresh: " + errorBody));
                                                    }
                                                })
                                        ).bodyToMono(String.class)
                                        .flatMap(responseBody -> {
                                            try {
                                                ApiRefreshTokenResponse tokenResponse = objectMapper.readValue(responseBody, ApiRefreshTokenResponse.class);
                                                String newRefreshToken = tokenResponse.getRefresh_token();
                                                tokenResponse.setSuccess(true);
                                                if (newRefreshToken != null && !newRefreshToken.equals(storedRefreshToken)) {
                                                    // Token rotation: save new refresh token + expiry
                                                    refreshTokenDocument.setRefreshToken(newRefreshToken);
                                                    refreshTokenDocument.setExpiresAt(Date.from(Instant.now().plusSeconds(2592000))); // e.g., 30 days
                                                    logger.info("The new refresh token document to be stored is as follows: {}",refreshTokenDocument);

                                                    return refreshTokenRepository.save(refreshTokenDocument)
                                                            .doOnSuccess(saved -> logger.info("The tokenResponse after successfuly storing the new refeshtoken in the db is as follows : {}",tokenResponse))
                                                            .thenReturn(tokenResponse);
                                                } else {
                                                    logger.info("The tokenResponse without having to store the refeshtoken in the db is as follows : {}",tokenResponse);
                                                    return Mono.just(tokenResponse);
                                                }
                                            } catch (Exception e) {
                                                logger.error("Failed to parse Auth0 refresh token response", e);
                                                return Mono.error(new RuntimeException("Failed to parse token response"));
                                            }
                                        });
                            })
                            .switchIfEmpty(Mono.defer(() -> {
                                // No token found for userId
                                ApiRefreshTokenResponse errorResponse = new ApiRefreshTokenResponse();
                                errorResponse.setErrorCode("REFRESH_TOKEN_NOT_FOUND");
                                errorResponse.setErrorMessage("Refresh token not found in database for user: " + request.getIdentifier());
                                errorResponse.setSuccess(false);
                                logger.error("Refresh token errorResponse {}", errorResponse);
                                return Mono.just(errorResponse);
                            }));
                })
                .onErrorResume(e -> {
                    logger.error("Refresh token process failed: {}", e.getMessage());
                    ApiRefreshTokenResponse errorResponse = new ApiRefreshTokenResponse();
                    errorResponse.setErrorCode("REFRESH_TOKEN_ERROR");
                    errorResponse.setErrorMessage(e.getMessage());
                    errorResponse.setSuccess(false);
                    logger.error("Refresh token errorResponse {}", errorResponse);
                    return Mono.just(errorResponse);
                });
    }
    @Override
    public Mono<ApiUserInfoResponse> getUserInfo(ApiUserInfoRequest request){
        if (request.getAccessToken() == null || request.getAccessToken().isBlank()) {
            return Mono.just(new ApiUserInfoResponse(null, "MISSING_ACCESS_TOKEN", "Access token is required."));
        }

        return webClient.get()
                .uri("https://"+ domain+"/userinfo")
                .headers(headers -> headers.setBearerAuth(request.getAccessToken()))
                .retrieve()
                .bodyToMono(Map.class)
                .map(userMap -> {
                    UserInfo userInfo = new UserInfo();
                    userInfo.setUserId((String) userMap.get("sub"));
                    userInfo.setName((String) userMap.get("name"));
                    userInfo.setEmail((String) userMap.get("email"));
                    userInfo.setEmailVerified(Boolean.TRUE.equals(userMap.get("email_verified")));
                    userInfo.setPicture((String) userMap.get("picture"));
                    userInfo.setLocale((String) userMap.get("locale"));
                    ApiUserInfoResponse apiUserInfoResponse = new ApiUserInfoResponse(userInfo, null, null);
                    logger.info("ApiUserInfoResponse is as follows : {}",apiUserInfoResponse);
                    return apiUserInfoResponse;
                })
                .onErrorResume(ex -> {
                    ApiUserInfoResponse error = new ApiUserInfoResponse();
                    error.setErrorCode("USER_INFO_FETCH_FAILED");
                    error.setErrorMessage("Failed to fetch user info: " + ex.getMessage());
                    logger.error("Error response is as follows : {}",error);
                    return Mono.just(error);
                });
    }

    @Override
    public Mono<ApiLogoutResponse> logout( ApiLogoutRequest request) {
        String baseLogoutUrl = "https://" + domain + "/v2/logout";
        String returnTo = request.getReturnToUrl() != null ? request.getReturnToUrl() : "https://www.google.com";

        String logoutUrl = UriComponentsBuilder
                .fromHttpUrl(baseLogoutUrl)
                .queryParam("client_id", clientId)
                .queryParam("returnTo", returnTo)
                .build()
                .toUriString();
       logger.info("logout uri: {}",logoutUrl);
        // I will now Trigger a GET call to ensure it's accessible
        return webClient.get()
                .uri(logoutUrl)
                .retrieve()
                .toBodilessEntity()
                .map(response -> new ApiLogoutResponse(true, "User logged out successfully.",logoutUrl))
                .doOnSuccess(resp -> logger.info("Logout success: {}", resp))
                .onErrorResume(ex -> {
                    logger.error("Logout failed: {}", ex.getMessage(), ex);
                    return Mono.just(new ApiLogoutResponse(false, "Logout failed: " + ex.getMessage(),""));
                });

    }
}
