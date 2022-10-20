package org.javaboy.multi_users03;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

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
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 当然，开发者也可以不使用Spring Security提供的默认的全局AuthenticationManager对象，
     * 而是通过重写configure(AuthenticationManagerBuilder)方法来自定义全局Authentication Manager对象：
     * 最新版本这种方式不行
     * 需要注意的是，一旦重写了configure(AuthenticationManagerBuilder)方法，那么全局AuthenticationManager对象中使用的用户，
     * 将以configure(AuthenticationManagerBuilder)方法中定义的用户为准。
     * 此时，如果我们还向Spring容器中注入了另外一个UserDetailsService实例，
     * 那么该实例中定义的用户将不会生效(因为AuthenticationConfiguration#getAuthenticationManager方法没有被调用)。
     *
     * @param auth the {@link AuthenticationManagerBuilder} to use
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("javagirl")
                .password("{noop}123")
                .roles("admin");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        users.createUser(User.withUsername("javaboy")
                .password("{noop}123").roles("admin").build());
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll()
                .and()
                .userDetailsService(users)
                .csrf().disable();
    }
}

