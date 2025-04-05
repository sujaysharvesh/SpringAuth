package com.example.userAuth.OAuth;

import java.util.Map;


public class GitHubOauth2UserInfo implements OAuth2UserInfo {
    public GitHubOauth2UserInfo(Map<String, Object> attributes) {
    }

    @Override
    public String getId() {
        return "";
    }

    @Override
    public String getName() {
        return "";
    }

    @Override
    public String getEmail() {
        return "";
    }
}
