package com.example.demo.controller;

import com.example.demo.util.JWTTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @Autowired
    private JWTTokenProvider jwtTokenProvider;

    @GetMapping("/home")
    public String home(@AuthenticationPrincipal OAuth2User oauthUser) {
        String jwtToken = jwtTokenProvider.createToken(oauthUser.getAttribute("email"));
        return "Welcome, " + oauthUser.getAttribute("name") + "! Your JWT Token: " + jwtToken;
    }

    @GetMapping("/secure-data")
    public String secureData() {
        return "This is a secure endpoint!";
    }
}
