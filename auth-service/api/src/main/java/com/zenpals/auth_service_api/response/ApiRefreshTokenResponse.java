package com.zenpals.auth_service_api.response;

import lombok.Data;

import java.io.Serializable;

@Data
public class ApiRefreshTokenResponse implements Serializable {
    private String id_token;
    private String access_token;
    private String token_type;
    private Integer expires_in;
    private String scope;
    private String refresh_token;

    // For error responses
    private String errorCode;
    private String errorMessage;

    private Boolean success;
}
