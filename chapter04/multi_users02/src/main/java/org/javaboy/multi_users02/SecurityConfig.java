package org.javaboy.multi_users02;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
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
    /**
     * 由于默认的全局AuthenticationManager在配置时会从Spring容器中查找UserDetailsService实例，
     * 所以我们如果针对全局AuthenticationManager配置用户，只需要往Spring容器中注入一个UserDetailsService实例即可
     *
     * @return
     */
    @Bean
    UserDetailsService us() {
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        users.createUser(User.withUsername("江南一点雨")
                .password("{noop}123").roles("admin").build());
        return users;
    }

    /**
     * 配置完成后，当我们启动项目时，全局的AuthenticationManager在配置时会去Spring容器中查找UserDetailsService实例，
     * 找到的就是我们自定义的UserDetailsService实例。当我们进行登录时，系统拿着我们输入的用户名／密码，
     * 首先和javaboy/123进行匹配，如果匹配不上的话，再去和江南一点雨/123进行匹配。
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        users.createUser(User.withUsername("javaboy")
                .password("{noop}123").roles("admin").build());
        return http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll()
                .and()
                .userDetailsService(users)
                .csrf().disable().build();
    }
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
//        users.createUser(User.withUsername("javaboy")
//                .password("{noop}123").roles("admin").build());
//        http.authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .permitAll()
//                .and()
//                .userDetailsService(users)
//                .csrf().disable();
//    }
}