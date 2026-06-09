package com.socdss.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class AuthService {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int MAX_FAILED_LOGINS = 5;
    private static final long LOCK_SECONDS = 300;

    private final AppUserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final ConcurrentMap<String, LoginAttempt> loginAttempts = new ConcurrentHashMap<>();

    public AuthService(AppUserRepository userRepository, PasswordHasher passwordHasher) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
    }

    public AuthStatus status(HttpSession session) {
        if (session == null) {
            return new AuthStatus(false, null, false, null);
        }
        Long userId = (Long) session.getAttribute(AuthSession.USER_ID);
        if (userId == null) {
            return new AuthStatus(false, null, false, null);
        }
        return userRepository.findById(userId)
                .filter(user -> Boolean.TRUE.equals(user.getEnabled()))
                .map(user -> new AuthStatus(true, user.getUsername(), Boolean.TRUE.equals(user.getMustChangePassword()), csrfToken(session)))
                .orElseGet(() -> new AuthStatus(false, null, false, null));
    }

    public AuthStatus login(LoginRequest request, HttpServletRequest servletRequest) {
        String username = request.username().trim();
        enforceLoginThrottle(username);
        AppUser user = userRepository.findByUsername(username)
                .filter(candidate -> Boolean.TRUE.equals(candidate.getEnabled()))
                .filter(candidate -> passwordHasher.verify(request.password(), candidate.getPasswordHash()))
                .orElse(null);
        if (user == null) {
            recordFailedLogin(username);
            throw new IllegalArgumentException("Invalid username or password");
        }
        loginAttempts.remove(attemptKey(username));
        HttpSession existingSession = servletRequest.getSession(false);
        if (existingSession != null) {
            existingSession.invalidate();
        }
        HttpSession session = servletRequest.getSession(true);
        session.setAttribute(AuthSession.USER_ID, user.getId());
        session.setAttribute(AuthSession.USERNAME, user.getUsername());
        session.setAttribute(AuthSession.CSRF_TOKEN, newCsrfToken());
        return new AuthStatus(true, user.getUsername(), Boolean.TRUE.equals(user.getMustChangePassword()), csrfToken(session));
    }

    public AuthStatus changePassword(ChangePasswordRequest request, HttpSession session) {
        Long userId = (Long) session.getAttribute(AuthSession.USER_ID);
        if (userId == null) {
            throw new IllegalArgumentException("Not authenticated");
        }
        if (request.newPassword() == null || request.newPassword().length() < 8) {
            throw new IllegalArgumentException("New password must have at least 8 characters");
        }
        AppUser user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("User not found"));
        if (!passwordHasher.verify(request.currentPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }
        user.setPasswordHash(passwordHasher.hash(request.newPassword()));
        user.setMustChangePassword(false);
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        return new AuthStatus(true, user.getUsername(), false, csrfToken(session));
    }

    public void logout(HttpSession session) {
        session.invalidate();
    }

    private String csrfToken(HttpSession session) {
        Object token = session.getAttribute(AuthSession.CSRF_TOKEN);
        if (token instanceof String value && !value.isBlank()) {
            return value;
        }
        String newToken = newCsrfToken();
        session.setAttribute(AuthSession.CSRF_TOKEN, newToken);
        return newToken;
    }

    private String newCsrfToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private void enforceLoginThrottle(String username) {
        LoginAttempt attempt = loginAttempts.get(attemptKey(username));
        if (attempt != null && attempt.lockedUntil() != null && attempt.lockedUntil().isAfter(Instant.now())) {
            throw new IllegalArgumentException("Invalid username or password");
        }
    }

    private void recordFailedLogin(String username) {
        loginAttempts.compute(attemptKey(username), (key, previous) -> {
            int failures = previous == null || (previous.lockedUntil() != null && previous.lockedUntil().isBefore(Instant.now()))
                    ? 1
                    : previous.failures() + 1;
            Instant lockedUntil = failures >= MAX_FAILED_LOGINS ? Instant.now().plusSeconds(LOCK_SECONDS) : null;
            return new LoginAttempt(failures, lockedUntil);
        });
    }

    private String attemptKey(String username) {
        return username.toLowerCase(Locale.ROOT);
    }

    private record LoginAttempt(int failures, Instant lockedUntil) {}
}
