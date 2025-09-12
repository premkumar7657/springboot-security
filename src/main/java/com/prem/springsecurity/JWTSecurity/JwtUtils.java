package com.prem.springsecurity.JWTSecurity;



import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;


@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private long jwtExpiryInMs = 100000; //10 minutes

    //getting jwt from header

 public String getJwtFromHeader(HttpServletRequest request)
 {
   String bearerToken = request.getHeader("authorization");
   logger.debug("Bearer token from header: {}", bearerToken);
   if(bearerToken !=null && bearerToken.startsWith("Bearer "))
   {
       return bearerToken.substring(7); //remove bearer prefix
   }
   return null;
 }


 //generating username from token
 public String generateTokenfromUsername(UserDetails userDetails)
 {
    
    String userName = userDetails.getUsername();
   
    return Jwts.builder()
    .subject(userName)
    .issuedAt(new Date())
    .expiration(new Date(new Date().getTime() + jwtExpiryInMs ))//10 minutes
    .signWith(key())
    .compact();
 }

 public String getUserNamefromToken(String token)
 {
    return Jwts.parser()
    .verifyWith(key())
    .build()
    .parseSignedClaimsJws(token)
    .getPayload()
    .getSubject();
 }
     



}
