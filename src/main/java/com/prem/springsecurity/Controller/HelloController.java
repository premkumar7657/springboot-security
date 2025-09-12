package com.prem.springsecurity.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

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

}
