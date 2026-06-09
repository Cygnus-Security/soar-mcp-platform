package com.socdss.auth;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class DefaultUserInitializer implements ApplicationRunner {
    private final AppUserRepository userRepository;
    private final PasswordHasher passwordHasher;

    public DefaultUserInitializer(AppUserRepository userRepository, PasswordHasher passwordHasher) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (userRepository.count() > 0) {
            return;
        }
        AppUser admin = new AppUser();
        admin.setUsername("admin");
        admin.setPasswordHash(passwordHasher.hash("admin"));
        admin.setMustChangePassword(true);
        admin.setEnabled(true);
        userRepository.save(admin);
    }
}
