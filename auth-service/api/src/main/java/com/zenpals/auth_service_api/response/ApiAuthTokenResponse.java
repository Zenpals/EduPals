package com.zenpals.auth_service_api.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApiAuthTokenResponse implements Serializable {
    private String id_token;
    private String access_token;
    private String token_type;
    private Integer expires_in;
    private String scope;
    private String refresh_token;
    private String refresh_token_identifier;
    // Fields for error response
    private String errorCode;
    private String errorMessage;
}
