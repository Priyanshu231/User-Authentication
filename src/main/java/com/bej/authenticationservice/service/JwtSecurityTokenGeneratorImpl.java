package com.bej.authenticationservice.service;

import com.bej.authenticationservice.domain.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtSecurityTokenGeneratorImpl implements SecurityTokenGenerator  {

//This method will generate the token

  @Override
  public Map<String, String> generateToken(User user) {
    String jwtToken = null;
//        to generate the token created logic and store the token in jwtToken variable.
//        Jwts.builder() is header,setSubject(user.getEmail()) is payload,setIssuedAt(new Date()) is the current date when the taken will be generated,signWith(SignatureAlgorithm.HS256,"securityKey") is signature securityKey is the key which will be used for match/creating process. compact() will make the token compact(combine 3 parts).
    jwtToken = Jwts.builder().setSubject(user.getUsername()).setIssuedAt(new Date()).signWith(SignatureAlgorithm.HS256,"securitykey").compact();
//        create a map object to store the token generated, because map can store multiple types of values..
    Map<String,String> map = new HashMap<>();
//        put will put the token in map object created
    map.put("token",jwtToken);
//        set the message to display when token will be created.
    map.put("message","successfully logged in");
//        then returning map which contains the token.
    return map;
  }
}

