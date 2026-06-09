package com.socdss.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/status")
    public AuthStatus status(HttpServletRequest request) {
        return authService.status(request.getSession(false));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthStatus> login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
        return ResponseEntity.ok(authService.login(request, servletRequest));
    }

    @PostMapping("/change-password")
    public ResponseEntity<AuthStatus> changePassword(@Valid @RequestBody ChangePasswordRequest request, HttpSession session) {
        return ResponseEntity.ok(authService.changePassword(request, session));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpSession session) {
        authService.logout(session);
        return ResponseEntity.noContent().build();
    }
}
