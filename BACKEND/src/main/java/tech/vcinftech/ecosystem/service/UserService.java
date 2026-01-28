package tech.vcinftech.ecosystem.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.vcinftech.ecosystem.domain.User;
import tech.vcinftech.ecosystem.repository.UserRepository;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    
    @Transactional(readOnly = true)
    public List<User> findAll() {
        return userRepository.findAll();
    }
    
    @Transactional(readOnly = true)
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }
    
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    
    @Transactional
    public User create(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new IllegalArgumentException("Username já existe");
        }
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new IllegalArgumentException("Email já existe");
        }
        return userRepository.save(user);
    }
    
    @Transactional
    public User update(Long id, User user) {
        User existing = userRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("User não encontrado"));
        
        existing.setFullName(user.getFullName());
        existing.setEmail(user.getEmail());
        existing.setActive(user.getActive());
        
        return userRepository.save(existing);
    }
    
    @Transactional
    public void delete(Long id) {
        userRepository.deleteById(id);
    }
}
