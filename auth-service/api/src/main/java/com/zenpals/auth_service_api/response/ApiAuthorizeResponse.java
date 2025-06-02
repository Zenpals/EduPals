package com.zenpals.auth_service_api.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ApiAuthorizeResponse implements Serializable {
    private String redirectUri;
    private String error;
    private String errorMessage;
}
