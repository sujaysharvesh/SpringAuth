package com.example.userAuth.User;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.UUID;

public class CustomUserDetails implements UserDetails {
    private String id;
    private String username;
    private String email;
    private Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(UUID id, String username, String email, Collection<? extends GrantedAuthority> authorities) {
        this.id = String.valueOf(id);
        this.username = username;
        this.email = email;
        this.authorities = authorities;
    }


    public String getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public String getUsername() {
        return username;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
