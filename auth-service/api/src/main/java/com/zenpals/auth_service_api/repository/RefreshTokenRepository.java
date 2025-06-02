package com.zenpals.auth_service_api.repository;


import com.zenpals.auth_service_api.domain.documents.RefreshTokenDocument;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;

public interface RefreshTokenRepository extends ReactiveMongoRepository<RefreshTokenDocument, String> {
    // Define custom queries here if needed.
//    None needed as of now.
}

