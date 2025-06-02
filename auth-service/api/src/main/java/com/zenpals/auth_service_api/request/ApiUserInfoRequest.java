package com.zenpals.auth_service_api.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApiUserInfoRequest {
    private String accessToken;
}
