package com.prem.springsecurity.SecurityConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {


    @Autowired
    DataSource dataSource;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http.authorizeHttpRequests(authz -> authz.requestMatchers("/h2-console/**").permitAll()
        .anyRequest().authenticated());

        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // No sessions will be created or used by Spring Security

        // Disable CSRF for the H2 console
          //http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"));
          http.csrf(csrf -> csrf.disable());
      http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin())); // Allow frames from the same origin (for H2 console)


        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
    }


    @Bean
    UserDetailsService userDetailsService()
    {

       // return username -> org.springframework.security.core.userdetails.User
       UserDetails user1 = User.withUsername("user1")
            .password(passwordEncoder().encode("user1"))
            .roles("USER")
            .build();

            UserDetails user2 = User.withUsername("admin1")
            .password(passwordEncoder().encode("admin1"))
            .roles("ADMIN")
            .build();


            JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager();

            jdbcUserDetailsManager.setDataSource(dataSource);

            jdbcUserDetailsManager.createUser(user1);
            jdbcUserDetailsManager.createUser(user2);

           return jdbcUserDetailsManager;

           // return new InMemoryUserDetailsManager(user1,user2);
           //https://github.com/spring-projects/spring-security/blob/main/core/src/main/resources/org/springframework/security/core/userdetails/jdbc/users.ddl
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    


}
