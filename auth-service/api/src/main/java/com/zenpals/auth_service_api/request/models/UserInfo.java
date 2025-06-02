package com.zenpals.auth_service_api.request.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserInfo {
    private String userId;
    private String name;
    private String email;
    private boolean emailVerified;
    private String picture;
    private String locale;
}
