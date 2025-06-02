package com.zenpals.auth_service_api;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.mongo.MongoReactiveDataAutoConfiguration;
import org.springframework.boot.autoconfigure.mongo.MongoReactiveAutoConfiguration;


@SpringBootApplication(
//		exclude = {
//				MongoReactiveAutoConfiguration.class,
//				MongoReactiveDataAutoConfiguration.class
//		}
)
public class AuthServiceApplication {
	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}
}
