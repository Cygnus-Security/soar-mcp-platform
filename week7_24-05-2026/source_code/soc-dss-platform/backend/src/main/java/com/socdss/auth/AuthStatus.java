package com.socdss.auth;

public record AuthStatus(
        boolean authenticated,
        String username,
        boolean mustChangePassword,
        String csrfToken
) {}
