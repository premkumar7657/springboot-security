package com.prem.springsecurity.JWTSecurity;



import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;


@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtExpiryInMs}")
    private long jwtExpiryInMs ;//10 minutes

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

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
    .verifyWith((SecretKey)key())
    .build()
    .parseSignedClaims(token)
    .getPayload()
    .getSubject();
 }
 //generate Signing key

 public Key key()
 {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));

  }

  //Validate JWT token
  
  public boolean validateToken( String token)
  {

      try{
         Jwts.parser()
         .verifyWith((SecretKey)key())
         .build()
         .parseSignedClaims(token);
         return true;
      }catch(MalformedJwtException e)
      {
         logger.error("Invalid JWT token: {}", e.getMessage());
      }
      catch(ExpiredJwtException e)
      {
         logger.error("JWT token is expired: {}", e.getMessage());
      }
      catch(UnsupportedJwtException e)
      {
         logger.error("JWT token is unsupported: {}", e.getMessage());
      }
      catch(IllegalArgumentException e)
      {
         logger.error("JWT claims string is empty: {}", e.getMessage());
      }
      catch (SignatureException e) { // 👈 Add this catch block
            logger.error("Invalid JWT signature: {}", e.getMessage());
      }
      return false;

  }

     



}
