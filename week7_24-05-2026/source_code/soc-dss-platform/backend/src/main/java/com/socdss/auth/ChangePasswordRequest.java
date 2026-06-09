package com.socdss.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotBlank @Size(max = 256) String currentPassword,
        @NotBlank @Size(min = 8, max = 256) String newPassword
) {}
