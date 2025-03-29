package com.example.userAuth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Collections;

@SpringBootApplication
public class UserAuthApplication {

	private static final Logger logger = LoggerFactory.getLogger(UserAuthApplication.class);

	public static void main(String[] args) {
		int port = 8081;
		SpringApplication app = new SpringApplication(UserAuthApplication.class);
		app.setDefaultProperties(Collections.singletonMap("server.port", port));
		app.run(args);
		logger.info("Application running successfully on port {}", port);
	}

}
