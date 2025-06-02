package com.zenpals.auth_service_api.controller;
import com.zenpals.auth_service_api.request.ApiLogoutRequest;
import com.zenpals.auth_service_api.request.ApiRefreshTokenRequest;
import com.zenpals.auth_service_api.request.ApiUserInfoRequest;
import com.zenpals.auth_service_api.response.*;
import com.zenpals.auth_service_api.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;


@RestController
@RequestMapping("/auth-service-api/auth")
public class AuthController {
    @Autowired
    private AuthService authService;
    @GetMapping("/authorize")
    public Mono<ApiAuthorizeResponse> authorize() {
      return authService.authorize();
    }
    @GetMapping("/code-for-token-exchange/{code}")
    public Mono<ApiAuthTokenResponse> exchangeCodeForToken(@PathVariable String code) {
      return authService.exchangeCodeForToken(code);
    }
    @PostMapping("/refresh-token")
    public Mono<ApiRefreshTokenResponse> refreshToken(@RequestBody Mono<ApiRefreshTokenRequest> requestMono) {
      return authService.refreshToken(requestMono);
    }
    @PostMapping("/user-info")
    public Mono<ApiUserInfoResponse> getUserInfo(@RequestBody ApiUserInfoRequest request) {
      return authService.getUserInfo(request);
    }
    @PostMapping("/logout")
    public Mono<ApiLogoutResponse> logout(@RequestBody ApiLogoutRequest request) {
      return authService.logout(request);
    }

}
