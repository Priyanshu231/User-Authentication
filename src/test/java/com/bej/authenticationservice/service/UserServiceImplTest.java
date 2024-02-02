package com.bej.authenticationservice.service;

import com.bej.authenticationservice.domain.User;
import com.bej.authenticationservice.exception.UserAlreadyExistException;
import com.bej.authenticationservice.exception.UserNotFoundException;
import com.bej.authenticationservice.repository.UserRepository;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.internal.verification.VerificationModeFactory;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserServiceImpl userService;

    private User user1;


    @BeforeEach
    void setUp() {
        user1 = new User(1001,"Johny","Johny123","Florida");
    }

    @AfterEach
    void tearDown() {
        user1=null;

    }
    @Test
    public void givenCustomerToSaveReturnSavedCustomerSuccess() throws UserAlreadyExistException {
        when(userRepository.findById(user1.getUserId())).thenReturn(Optional.ofNullable(null));
        when(userRepository.save(any())).thenReturn(user1);
        assertEquals(user1,userService.saveUser(user1));
        verify(userRepository,times(1)).save(any());
        verify(userRepository,times(1)).findById(any());
    }

    @Test
    public void givenCustomerToDeleteShouldDeleteSuccess() throws UserNotFoundException {
        when(userRepository.findById(user1.getUserId())).thenReturn(Optional.ofNullable(user1));
        boolean flag = userService.deleteUser(user1.getUserId());
        assertTrue(flag);

        verify(userRepository, VerificationModeFactory.times(1)).deleteById(any());
        verify(userRepository, VerificationModeFactory.times(1)).findById(any());
    }



}