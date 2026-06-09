package com.socdss.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Set;

@Component
public class AuthInterceptor implements HandlerInterceptor {
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");
    private static final String CSRF_HEADER = "X-CSRF-Token";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();
        if (path.equals("/api/v1/health") || path.equals("/api/v1/auth/status") || path.equals("/api/v1/auth/login")) {
            return true;
        }
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute(AuthSession.USER_ID) == null) {
            writeError(response, HttpServletResponse.SC_UNAUTHORIZED, "Authentication required");
            return false;
        }

        if (!SAFE_METHODS.contains(request.getMethod().toUpperCase()) && !validCsrfToken(request, session)) {
            writeError(response, HttpServletResponse.SC_FORBIDDEN, "CSRF token required");
            return false;
        }
        return true;
    }

    private boolean validCsrfToken(HttpServletRequest request, HttpSession session) {
        Object expected = session.getAttribute(AuthSession.CSRF_TOKEN);
        String actual = request.getHeader(CSRF_HEADER);
        return expected instanceof String token && actual != null && token.equals(actual);
    }

    private void writeError(HttpServletResponse response, int status, String message) throws Exception {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }
}
