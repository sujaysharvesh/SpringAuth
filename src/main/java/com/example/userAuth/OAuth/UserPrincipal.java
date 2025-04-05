package com.example.userAuth.OAuth;

import com.example.userAuth.User.User;
import com.example.userAuth.User.User.AuthProvider;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.*;
import java.util.stream.Collectors;

public class UserPrincipal implements OidcUser {
    private UUID id;
    private String email;
    private String name;
    private AuthProvider provider;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;
    private OidcIdToken idToken;
    private OidcUserInfo userInfo;

    // Updated constructor
    private UserPrincipal(UUID id, String email, String name,
                          Collection<? extends GrantedAuthority> authorities,
                          Map<String, Object> attributes,
                          AuthProvider provider,
                          OidcIdToken idToken,
                          OidcUserInfo userInfo) {
        this.id = id;
        this.email = email;
        this.name = name;
        this.authorities = authorities;
        this.attributes = attributes;
        this.provider = provider;
        this.idToken = idToken;
        this.userInfo = userInfo;
    }

    // Factory method
    public static UserPrincipal localLogin(User user) {
        Collection<GrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_USER")
        );

        return new UserPrincipal(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                authorities,
                null,
                user.getProvider(),
                null,
                null
        );
    }

    public static UserPrincipal create(User user, Map<String, Object> attributes,
                                       OidcIdToken idToken, OidcUserInfo userInfo) {
        Collection<GrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_USER")
        );

        return new UserPrincipal(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                authorities,
                attributes,
                user.getProvider(),
                idToken,
                userInfo
        );
    }

    public static UserPrincipal create(Claims claims) {
        return new UserPrincipal(
                UUID.fromString(claims.getSubject()),
                claims.get("email", String.class),
                claims.get("name", String.class),
                claims.get("roles") == null ?
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")) :
                        ((List<String>) claims.get("roles")).stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList()),
                null,
                AuthProvider.valueOf(claims.get("auth_provider", String.class)),
                null,
                null
        );
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes != null ? attributes : Collections.emptyMap();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Map<String, Object> getClaims() {
        return Map.of();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return userInfo;
    }

    @Override
    public OidcIdToken getIdToken() {
        return idToken;
    }

    // Additional getters
    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public AuthProvider getProvider() {
        return provider;
    }

    public void setProvider(AuthProvider provider) {
        this.provider = provider;
    }
}
