package com.example.userAuth.OAuth;

import com.example.userAuth.User.User;
import com.example.userAuth.User.User.AuthProvider;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.*;
import java.util.stream.Collectors;


public class UserPrincipal implements OAuth2User {
    private UUID id;
    private String email;
    private String name;
    private AuthProvider provider;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    // Private constructor
    private UserPrincipal(UUID id, String email, String name,
                          Collection<? extends GrantedAuthority> authorities,
                          Map<String, Object> attributes, AuthProvider provider) {
        this.id = id;
        this.email = email;
        this.name = name;
        this.authorities = authorities;
        this.attributes = attributes;
        this.provider = provider;
    }

    // Factory method
    public static UserPrincipal create(User user, Map<String, Object> attributes) {
        // Convert your user roles/privileges to GrantedAuthority objects
        Collection<GrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_USER") // Default role
        );

        return new UserPrincipal(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                authorities,
                attributes,
                user.getProvider()
        );
    }
    public static UserPrincipal create(Claims claims) {
        UserPrincipal principal = new UserPrincipal(
                UUID.fromString(claims.getSubject()), // Convert String to UUID
                claims.get("email", String.class),
                claims.get("name", String.class),
                claims.get("roles") == null ?
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")) :
                        ((List<String>) claims.get("roles")).stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList()),
                null, // No attributes for JWT
                AuthProvider.valueOf(claims.get("auth_provider", String.class))
        );
        return principal;
    }


    // Implement OAuth2User methods
    @Override
    public Map<String, Object> getAttributes() {
        return attributes != null ? attributes : Collections.emptyMap();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities != null ? authorities : Collections.emptyList();
    }

    @Override
    public String getName() {
        return name;
    }

    // Additional getters
    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }
    public User.AuthProvider getProvider() {
        return provider;
    }

    public void setProvider(User.AuthProvider provider) {
        this.provider = provider;
    }
}