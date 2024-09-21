package br.com.autentication.securitybootconfig.controller;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeConfig -> {
            authorizeConfig.requestMatchers("/public", "/logout").permitAll();
            authorizeConfig.anyRequest().authenticated();
        });

        http.oauth2Login(Customizer.withDefaults());
        http.oauth2ResourceServer(config -> config.jwt(Customizer.withDefaults()));

        return http.build();
    }
}
