package com.example.userAuth.OAuth;

import com.example.userAuth.User.User;

import com.example.userAuth.User.User.AuthProvider;
import java.util.Map;

import static org.springframework.security.config.oauth2.client.CommonOAuth2Provider.GOOGLE;
import static org.springframework.security.config.oauth2.client.CommonOAuth2Provider.GITHUB;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2InfoFactory(AuthProvider provider, Map<String, Object> attributes) {
        return switch (provider) {
            case GOOGLE -> new GoogleOAuth2UserInfo(attributes);
            case GITHUB ->  new GitHubOauth2UserInfo(attributes);
            default -> throw new IllegalStateException("Unexpected value: " + provider);
        };
    }
}



