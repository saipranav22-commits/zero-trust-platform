package com.zerotrust.service;

import com.zerotrust.entity.User;
import com.zerotrust.entity.Role;
import com.zerotrust.exception.ResourceNotFoundException;
import com.zerotrust.exception.ValidationException;
import com.zerotrust.repository.RoleRepository;
import com.zerotrust.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository  userRepository;
    private final RoleRepository  roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public Page<User> findAll(String email, Boolean isActive, Pageable pageable) {
        return userRepository.searchUsers(email, isActive, pageable);
    }

    @Transactional(readOnly = true)
    public User findById(UUID id) {
        return userRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("User not found: " + id));
    }

    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
            .orElseThrow(() -> new ResourceNotFoundException("User not found: " + email));
    }

    @Transactional
    public User update(UUID id, String firstName, String lastName, Boolean isActive) {
        User user = findById(id);
        if (firstName != null) user.setFirstName(firstName);
        if (lastName  != null) user.setLastName(lastName);
        if (isActive  != null) user.setActive(isActive);
        return userRepository.save(user);
    }

    @Transactional
    public User updateRoles(UUID userId, List<String> roleNames) {
        User user = findById(userId);
        List<Role> roles = roleRepository.findByNameIn(roleNames);
        if (roles.size() != roleNames.size()) {
            throw new ValidationException("One or more roles not found: " + roleNames);
        }
        user.setRoles(new HashSet<>(roles));
        log.info("Updated roles for user {}: {}", user.getEmail(), roleNames);
        return userRepository.save(user);
    }

    @Transactional
    public User unlockUser(UUID id) {
        User user = findById(id);
        user.setLocked(false);
        user.setFailedLoginAttempts(0);
        user.setLockUntil(null);
        log.info("Unlocked user: {}", user.getEmail());
        return userRepository.save(user);
    }

    @Transactional
    public void deactivate(UUID id) {
        User user = findById(id);
        user.setActive(false);
        userRepository.save(user);
        log.info("Deactivated user: {}", user.getEmail());
    }
}
