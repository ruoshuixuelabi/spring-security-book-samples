package org.javaboy.multi_filter_chain;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    UserDetailsService us1() {
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        users.createUser(User.withUsername("javaboy").password("{noop}123").roles("admin").build());
        return users;
    }

    UserDetailsService us2() {
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        users.createUser(User.withUsername("javagirl")
                .password("{noop}123").roles("admin").build());
        return users;
    }

    @Bean
    SecurityFilterChain securityFilterChain01(HttpSecurity http) throws Exception {
        return http.antMatcher("/bar/**")
                .userDetailsService(us1())
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/bar/login")
                .successHandler((req, resp, auth) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    String s = new ObjectMapper().writeValueAsString(auth);
                    System.out.println(s);
                    resp.getWriter().write(s);
                })
                .permitAll()
                .and()
                .csrf().disable()
                .build();
    }


    @Bean
    SecurityFilterChain SecurityFilterChain02(HttpSecurity http) throws Exception {
        return http.antMatcher("/foo/**")
                .userDetailsService(us2())
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/foo/login")
                .successHandler((req, resp, auth) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    String s = new ObjectMapper().writeValueAsString(auth);
                    resp.getWriter().write(s);
                })
                .permitAll()
                .and()
                .csrf().disable()
                .build();
    }
}