package com.zenpals.auth_service_api.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApiRefreshTokenRequest implements Serializable {
    private String accessToken;
    private String identifier;
}
