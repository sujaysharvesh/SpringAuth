package com.example.userAuth.User;


import java.util.UUID;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;


@Entity
@Table(name = "Users")
public class User {

    @Id
    @GeneratedValue(strategy= GenerationType.UUID)
    @Column(nullable = false, unique = true)
    private UUID id;

    @NotNull(message = "Username is required")
    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Email(message = "Valid email is required")
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "password", nullable = true)
    private String password;

    @Column(name = "verified", nullable = false)
    private boolean verified = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider")
    private AuthProvider Provider;

    @Column(name = "providerId")
    private String providerId;

    public User(String email, String hashedPassword, String username, boolean b) {
    }

    public enum AuthProvider{
        LOCAL, GOOGLE, GITHUB

    }

    // Default constructor (needed for JPA)
    public User() {}

    // Parameterized constructor
    public User(String email, String password, String username, Boolean verified, String providerId, AuthProvider provider) {
        this.email = email;
        this.password = password;
        this.username = username;
        this.providerId = providerId;
        this.Provider = provider;
        this.verified = verified;
    }

    public static User createOAuthUser(String email, String username, String providerId, AuthProvider provider) {
        User user = new User();
        user.setEmail(email);
        user.setUsername(username);
        user.setProviderId(providerId);
        user.setProvider(provider.toString());
        return user;
    }

    public static User createLocalUser(String email, String password, String username) {
        User user = new User();
        user.setEmail(email);
        user.setPassword(password);
        user.setUsername(username);
        user.setVerified(false);
        return user;
    }

    // Getters and Setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public boolean getVerified() { return verified; }
    public void setVerified(boolean verified) { this.verified = verified; }
    public AuthProvider getProvider() {
        return Provider;
    }

    public boolean isVerified() {
        return verified;
    }
    public void setProvider(String provider) {
        this.Provider = AuthProvider.valueOf(provider);
    }

    public void setProviderId(String providerId) {
        this.providerId = providerId;
    }
}
