package com.zenpals.auth_service_api.domain.documents;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.Instant;
import java.util.Date;

@Document(collection = "refresh_tokens")
@Data
public class RefreshTokenDocument {
    @Id
    private String id;  // e.g., userId or sessionId or any unique key

    private String refreshToken;

    @Indexed(expireAfter = "0s")
    private Date expiresAt;
}

