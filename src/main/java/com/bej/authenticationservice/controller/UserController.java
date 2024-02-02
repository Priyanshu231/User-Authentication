package com.bej.authenticationservice.controller;


import com.bej.authenticationservice.domain.User;
import com.bej.authenticationservice.exception.UserAlreadyExistException;
import com.bej.authenticationservice.service.SecurityTokenGenerator;
import com.bej.authenticationservice.service.UserService;
import com.bej.authenticationservice.exception.UserNotFoundException;
import com.bej.authenticationservice.service.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/api/vi")
public class UserController {
    private ResponseEntity responseEntity;
    private UserService userService;
    private SecurityTokenGenerator securityTokenGenerator;
    /*
     * Autowiring should be implemented for the UserService and SecurityTokenGenerator. (Use Constructor-based
     * autowiring) Please note that we should not create an object using the new
     * keyword
     */
    @Autowired
    public UserController(UserServiceImpl userService,SecurityTokenGenerator securityTokenGenerator){
        this.userService=userService;
        this.securityTokenGenerator=securityTokenGenerator;
    }

    // first step - register the User

    /*
     * Define a handler method which will save a specific User by reading the
     *  object from request body and save the User details in the
     * database. This handler method should return any one of the status messages
     * basis on different situations:
     * 1. 201(CREATED) - If the user saved successfully.
     * 2. 500(INTERNAL_SERVER_ERROR) - If the User already exists
     *
     * This handler method should map to the URL "/register" using HTTP POST method
     */
    @PostMapping("/user")
    public ResponseEntity saveUser(@RequestBody User user) throws UserAlreadyExistException{
        try {
            User user1 = userService.saveUser(user);
            responseEntity = new ResponseEntity<>(user1,HttpStatus.CREATED);
        }
        catch (UserAlreadyExistException exception){
            responseEntity = new ResponseEntity<>(exception.getMessage(),HttpStatus.INTERNAL_SERVER_ERROR);
            throw new UserAlreadyExistException();
        }
        return responseEntity;
    }



    // second step - login the customer


    /* Define a handler method which will authenticate a User by reading the User
     * object from request body containing the username and password. The username and password should be validated
     * before proceeding ahead with JWT token generation. The User credentials will be validated against the database entries.
     * The error should be return if validation is not successful. If credentials are validated successfully, then JWT
     * token will be generated. The token should be returned back to the caller along with the API response.
     * This handler method should return any one of the status messages basis on different
     * situations:
     * 1. 200(OK) - If login is successful
     * 2. 401(UNAUTHORIZED) - If login is not successful
     *
     * This handler method should map to the URL "/login" using HTTP POST method
     */
    @PostMapping("/login")
    public ResponseEntity userLogin(@RequestBody User user) throws UserNotFoundException{
        Map<String,String> map =null;
        try {
            User customer1 = userService.findByUsernameAndPassword(user.getUsername(), user.getPassword());
            if (user.getUsername().equals(customer1.getUsername())){
                map = securityTokenGenerator.generateToken(user);
            }
            responseEntity = new ResponseEntity<>(map,HttpStatus.OK);
        }
        catch (UserNotFoundException exception){
            responseEntity = new ResponseEntity<>(exception.getMessage(),HttpStatus.UNAUTHORIZED);
        }
        return responseEntity;
    }



    //     Define a handler method that will get all  User from the database the
//     handler mapping url will be "/api/v1/userservice/users"
//    Status will be
//    1. 200(OK) - If all Users are successfully retrieved
//    2. 500(INTERNAL_SERVER_ERROR) - If any other error occurs
    @GetMapping("/token/users")
    public ResponseEntity getAllUser(){
        try {
            responseEntity = new ResponseEntity<>(userService.getAllUsers(),HttpStatus.OK);
        }
        catch (Exception exception){
            responseEntity = new ResponseEntity(exception.getMessage(),HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return responseEntity;
    }


    //    Define a handler method that will delete a  User
    //    the handler mapping url will be "/api/v1/userservice/{userId}"
//    Status will be
//    1. 200(OK) - If delete is successful
//    2. 500(INTERNAL_SERVER_ERROR) - If any other error occurs

    @DeleteMapping("/token/user/{userId}")
    public ResponseEntity deleteUser(@PathVariable int userId) throws UserNotFoundException{
        try {
            userService.deleteUser(userId);
            responseEntity = new ResponseEntity<>("Successfully Deleted",HttpStatus.OK);
        }
        catch (UserNotFoundException exception){
            responseEntity = new ResponseEntity<>(exception.getMessage(),HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return responseEntity;
    }





}
