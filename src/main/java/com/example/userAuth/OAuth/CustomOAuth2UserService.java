package com.example.userAuth.OAuth;

import com.example.userAuth.User.User;
import com.example.userAuth.User.UserRepository;
import com.example.userAuth.User.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import com.example.userAuth.User.User.AuthProvider;

import java.util.Optional;


@Service
public class CustomOAuth2UserService extends OidcUserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        AuthProvider provider = AuthProvider.valueOf(registrationId.toUpperCase());

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2InfoFactory(provider, oidcUser.getAttributes());
        Optional<User> userOptional = userRepository.findByEmail(userInfo.getEmail());
        User user;
        if(userOptional.isPresent()) {
            user = userOptional.get();
            if(!user.getProvider().equals(provider)) {
                throw new OAuth2AuthenticationException(
                        "You're signed up with " + user.getProvider() +
                                "account. Please use you " + user.getProvider() + "account to login"
                );
            }
            user = updateExistingUser(user, userInfo);
        } else {
            user = registerNewuser(provider, userInfo);
        }
        return UserPrincipal.create(user, oidcUser.getAttributes(), oidcUser.getIdToken(), oidcUser.getUserInfo());
    }


    private User registerNewuser(AuthProvider provider, OAuth2UserInfo userInfo) {
        User user = User.createOAuthUser(userInfo.getEmail(), userInfo.getName(), userInfo.getId(), provider);
        user.setUsername(userInfo.getName());
        user.setEmail(userInfo.getEmail());
        user.setProvider(String.valueOf(provider));
        user.setProviderId(userInfo.getId());
        user.setVerified(true);
        return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo userInfo) {
        existingUser.setUsername(userInfo.getName());
        return userRepository.save(existingUser);
    }
}

