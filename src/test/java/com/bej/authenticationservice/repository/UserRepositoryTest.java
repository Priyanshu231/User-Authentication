package com.bej.authenticationservice.repository;

import com.bej.authenticationservice.domain.User;
import com.bej.authenticationservice.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;
    private User user;
    @BeforeEach
    void setUp() {
        user = new User(1001, "Jonny", "Jonny123", "Florida");
    }
    @AfterEach
    void tearDown() {
        user = null;
        userRepository.deleteAll();
    }
    @Test
    @DisplayName("Test case for saving user object")
    void givenUserToSaveShouldReturnSavedUser() {

        userRepository.save(user);
        User user1 = userRepository.findById(user.getUserId()).get();
        assertNotNull(user1);
        assertEquals(user.getUserId(), user1.getUserId());
    }

    @Test
    @DisplayName("Test case for deleting user object")
    public void givenUserToDeleteShouldDeleteUser() {
        userRepository.save(user);
        User customer1 = userRepository.findById(user.getUserId()).get();
        userRepository.delete(customer1);
        assertEquals(Optional.empty(), userRepository.findById(user.getUserId()));

    }

}