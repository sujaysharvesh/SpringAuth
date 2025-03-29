package com.example.userAuth.User;

import com.example.userAuth.User.DTO.LoginRequestDTO;
import com.example.userAuth.User.DTO.UserDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserServices userServices;

    @Autowired
    private UserDTO userDTO;

    @GetMapping("/")
    public String Home() {
        return "Hello";
    }

    @GetMapping("/me")
    public String getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "No authenticated user";
        }
        return "Current User: " + authentication.getName();
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> registerUser(@Valid @RequestBody User user) {
        try {
            User newUser = userServices.registerUser(user.getUsername(), user.getEmail(), user.getPassword());
            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(newUser.getUsername());
            userDTO.setEmail(newUser.getEmail());
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("message", "User Registered Successfully", "user", newUser));
        } catch (DataIntegrityViolationException ex) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("message", "Email or username already exists"));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Something went wrong", "details", ex.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> loginUser(@Valid @RequestBody LoginRequestDTO loginRequestDTO){
        try {
            String token = userServices.loginUser(loginRequestDTO.getEmail(), loginRequestDTO.getPassword());
            return ResponseEntity.status(HttpStatus.OK)
                    .body(Map.of("message", "User Logged In Successfully", "token", token));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Something went wrong", "details", ex.getMessage()));
        }
    }

    @GetMapping("/logout")
    public ResponseEntity<Map<String, Object>> logoutUser(HttpServletRequest request) {
        try {
            userServices.logoutUser(request);
            return ResponseEntity.status(HttpStatus.OK)
                    .body(Map.of("message", "User Logged Out Successfully"));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Something went wrong", "details", ex.getMessage()));
        }
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Map<String, Object>> deleteUser(@Valid @RequestBody LoginRequestDTO loginRequestDTO) {
        try {
            userServices.deleteUser(loginRequestDTO.getEmail(), loginRequestDTO.getPassword());
            return ResponseEntity.status(HttpStatus.OK)
                    .body(Map.of("message", "User Deleted Successfully"));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Something went wrong", "details", ex.getMessage()));
        }
    }

}
