package com.example.userAuth.User;


import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;


@Service
public interface UserServices {
    User registerUser(String username, String email, String password);
    Optional<User> getAllUser();
    String loginUser(String email, String password);
    User updateUser(User user);
    boolean deleteUser(String email, String password);
    String currentUser();
    void logoutUser(HttpServletRequest request);
}
