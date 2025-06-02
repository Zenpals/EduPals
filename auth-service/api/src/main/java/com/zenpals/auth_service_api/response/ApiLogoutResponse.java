package com.zenpals.auth_service_api.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApiLogoutResponse {
    private boolean success;
    private String message;
    private String logout_uri;
}
