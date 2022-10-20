package org.javaboy.ignoredrequests;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author 江南一点雨
 * @微信公众号 江南一点雨
 * @网站 http://www.itboyhub.com
 * @国际站 http://www.javaboy.org
 * @微信 a_java_boy
 * @GitHub https://github.com/lenve
 * @Gitee https://gitee.com/lenve
 */
@Configuration
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
public class SecurityConfig {
    //    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring().antMatchers("/login.html", "/css/**", "/js/**","/images/**");
//    }
    @Bean
    public WebSecurityCustomizer ignoringCustomizer() {
        //2022-10-19 13:32:17.761  WARN 4684 --- [           main] o.s.s.c.a.web.builders.WebSecurity       :
        // You are asking Spring Security to ignore Ant [pattern='/images/**']. This is not recommended --
        // please use permitAll via HttpSecurity#authorizeHttpRequests instead.
        return (web) -> web.ignoring().antMatchers("/login.html", "/css/**", "/js/**", "/images/**");
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .csrf().disable().build();
    }
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .and()
//                .csrf().disable();
//    }
}
