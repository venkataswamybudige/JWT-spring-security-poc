package com.security.Spring_security_project;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.authorizeHttpRequests(registery -> {
            registery.requestMatchers("/home").permitAll();
            registery.requestMatchers("/admin/**").hasRole("ADMIN");
            registery.requestMatchers("/user/**").hasRole("USER");
            registery.anyRequest().authenticated();
        }).build();
    }
}
