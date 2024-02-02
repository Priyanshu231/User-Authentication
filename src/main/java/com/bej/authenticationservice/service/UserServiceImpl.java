package com.bej.authenticationservice.service;


import com.bej.authenticationservice.domain.User;
import com.bej.authenticationservice.exception.UserAlreadyExistException;
import com.bej.authenticationservice.exception.UserNotFoundException;
import com.bej.authenticationservice.repository.UserRepository;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;



@Service
public class UserServiceImpl implements UserService {

    //Autowire Repository layer
    private UserRepository userRepository;
    @Autowired
    public UserServiceImpl (UserRepository userRepository){
        this.userRepository=userRepository;

    }

    @Override
    public User saveUser(User user) throws UserAlreadyExistException {
        //check if User is present if condition is true then throw the exception UserAlreadyExistException
        //else save the User object
        //and return the saved User object
        if (userRepository.findById(user.getUserId()).isPresent()){
            throw new UserAlreadyExistException();
        }
        return userRepository.save(user);
    }

    @Override
    public User findByUsernameAndPassword(String username , String password) throws UserNotFoundException {
        // get the User by calling findByUsernameAndPassword method
        // if User is not null then return the User object
        User user = userRepository.findByUsernameAndPassword(username, password);

        if (user==null){
            throw new UserNotFoundException();
        }

        return user;


    }

    @Override
    public List<User> getAllUsers()  {
        // return all the customer from database
        return userRepository.findAll();
    }

    @Override
    public boolean deleteUser(int userId) throws UserNotFoundException {
        //find the userId if its empty then throw UserNotFoundException
        //else delete the user
        //return true if successfully deleted
        boolean flag = false;
        if (userRepository.findById(userId).isEmpty()){
            throw new UserNotFoundException();
        }
        else {
            userRepository.deleteById(userId);
            flag= true;
        }

        return flag;

    }

}
