package com.kodnest.app.usercontrollers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kodnest.app.entities.LoginRequest;
import com.kodnest.app.entities.User;
import com.kodnest.app.userservices.AuthServiceContract;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@CrossOrigin(origins = "https://kartnova-frontend.vercel.app", allowCredentials = "true")
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthServiceContract authService;

    public AuthController(AuthServiceContract authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        try {
            User user = authService.authenticate(loginRequest.getUsername(), loginRequest.getPassword());
            String token = authService.generateToken(user);

            Cookie cookie = new Cookie("authToken", token);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(3600);

            response.addCookie(cookie);

            response.addHeader(
                    "Set-Cookie",
                    String.format(
                            "authToken=%s; HttpOnly; Secure; Path=/; Max-Age=3600; SameSite=None",
                            token));

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("message", "Login successful");
            responseBody.put("role", user.getRole().name());
            responseBody.put("username", user.getUsername());

            return ResponseEntity.ok(responseBody);

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request,
                                                      HttpServletResponse response) {

        try {

            User user = (User) request.getAttribute("authenticatedUser");

            authService.logout(user);

            Cookie cookie = new Cookie("authToken", null);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            cookie.setMaxAge(0);

            response.addCookie(cookie);

            response.addHeader(
                    "Set-Cookie",
                    "authToken=; HttpOnly; Secure; Path=/; Max-Age=0; SameSite=None");

            Map<String, String> responseBody = new HashMap<>();
            responseBody.put("message", "Logout successful");

            return ResponseEntity.ok(responseBody);

        } catch (RuntimeException e) {

            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("message", "Logout failed");

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(errorResponse);
        }
    }
}