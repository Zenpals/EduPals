package com.zenpals.auth_service_api.response;


import com.zenpals.auth_service_api.request.models.UserInfo;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApiUserInfoResponse {
    private UserInfo userInfo;
    private String errorCode;
    private String errorMessage;
}
