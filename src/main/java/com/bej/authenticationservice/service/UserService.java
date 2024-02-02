package com.bej.authenticationservice.service;

import com.bej.authenticationservice.domain.User;
import com.bej.authenticationservice.exception.UserAlreadyExistException;
import com.bej.authenticationservice.exception.UserNotFoundException;

import java.util.List;


public interface UserService {

   User saveUser(User user) throws UserAlreadyExistException;
   User findByUsernameAndPassword(String username , String password) throws UserNotFoundException;
   List<User> getAllUsers();
   boolean deleteUser(int userId) throws UserNotFoundException;


}
