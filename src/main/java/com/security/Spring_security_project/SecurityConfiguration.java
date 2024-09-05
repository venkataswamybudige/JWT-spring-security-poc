package com.security.Spring_security_project;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.authorizeHttpRequests(registery -> {
            registery.requestMatchers("/home").permitAll();
            registery.requestMatchers("/admin/**").hasRole("ADMIN");
            registery.requestMatchers("/user/**").hasRole("USER");
            registery.anyRequest().authenticated();
        }).formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                .build();
    }

    @Bean
    public UserDetailsService userDetailsservice(){
        UserDetails normalUser = User.builder().
                username("venkat").
                password("$2a$12$0/Vm6LwyqkrGYP/B91lPQ..eVuvLyyJ9VkH7Km/hfJZIu9xchL98i").
                roles("USER") //1234
        .build();
        UserDetails adminUser = User.builder().
                username("admin").
                password("$2a$12$qMsr1ZiXweKQ5SYlcJded.AtHl/ipd46uI6ZKbkc7W0BDjl7/oo06").
                roles("ADMIN","USER")
                .build(); //9876
        return  new InMemoryUserDetailsManager(normalUser,adminUser);
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }
}
