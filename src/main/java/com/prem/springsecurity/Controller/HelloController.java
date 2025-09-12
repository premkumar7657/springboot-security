package com.prem.springsecurity.Controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.prem.springsecurity.JWTSecurity.JwtUtils;
import com.prem.springsecurity.JWTSecurity.LoginRequest;
import com.prem.springsecurity.JWTSecurity.LoginResponse;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
public class HelloController {


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    @GetMapping("/hello")
    public String hello()
    {
        return "hello";
    }


    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String helloAdmin()
    {
        return "hello admin";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String helloUser()
    {
        return "hello user";
    }


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        // Authenticate the user using the provided credentials
        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUserName(), loginRequest.getPassword())
            );
            
        } catch (AuthenticationException e) {
            Map<String,Object> map = new HashMap<>();
            map.put("message", "Bad Credentials");
            map.put("status", false);
            return new ResponseEntity<>(map,HttpStatus.NOT_FOUND);
        }

        // If authentication is successful, generate a JWT token
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwt = jwtUtils.generateTokenfromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(lis -> lis.getAuthority())
                .toList();

                LoginResponse loginResponse = new LoginResponse(jwt, userDetails.getUsername(), roles);

        return ResponseEntity.ok(loginResponse);
    }
    

}
