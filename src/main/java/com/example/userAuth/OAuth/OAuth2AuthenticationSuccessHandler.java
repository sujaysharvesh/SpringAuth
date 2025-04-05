package com.example.userAuth.OAuth;

import com.example.userAuth.User.UserRepository;
import com.example.userAuth.User.security.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.util.Map;


@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws java.io.IOException {

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        // Generate JWT token (same as your regular login)
        String token = jwtUtil.generateTokenFromUserPrincipal(userPrincipal);

        // Return token in response (or redirect with token)
        response.setContentType("application/json");
        response.getWriter().write(
                new ObjectMapper().writeValueAsString(
                        Map.of("token", token,
                                "userId", userPrincipal.getId(),
                                "email", userPrincipal.getEmail())
                )
        );
    }
}
