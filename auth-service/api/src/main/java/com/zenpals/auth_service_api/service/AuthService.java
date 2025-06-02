package com.zenpals.auth_service_api.service;

import com.zenpals.auth_service_api.request.ApiLogoutRequest;
import com.zenpals.auth_service_api.request.ApiRefreshTokenRequest;
import com.zenpals.auth_service_api.request.ApiUserInfoRequest;
import com.zenpals.auth_service_api.response.*;
import reactor.core.publisher.Mono;

public interface AuthService {

     Mono<ApiAuthorizeResponse> authorize();
     Mono<ApiAuthTokenResponse> exchangeCodeForToken(String code);
     Mono<ApiRefreshTokenResponse> refreshToken(Mono<ApiRefreshTokenRequest> requestMono);
     Mono<ApiUserInfoResponse> getUserInfo(ApiUserInfoRequest request);
     Mono<ApiLogoutResponse> logout(ApiLogoutRequest request);
}
