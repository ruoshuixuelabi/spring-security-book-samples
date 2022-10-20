package org.javaboy.multi_users01;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
     * 针对局部 AuthenticationManager 定义的用户
     * 当我们启动项目时，在IDEA控制台输出的日志中可以看到如下内容
     * Using generated security password: 65833cf6-197c-4f99-b851-9779cd9fc6ad
     * 这个是系统自动生成的用户，那么我们是否可以使用系统自动生成的用户进行登录呢？答案是可以的，为什么呢？
     * 回顾2.1.2.1小节，系统自动提供的用户对象实际上就是往Spring容器中注册了一个InMemoryUserDetailsManager对象。
     * 而在前面的代码中，我们没有重写configure(AuthenticationManagerBuilder)方法，
     * 这意味着全局的`AuthenticationManager`是通过AuthenticationConfiguration#getAuthenticationManager方法自动生成的，
     * 在生成的过程中，会从Spring容器中查找对应的`UserDetailsService`实例进行配置(具体配置在`InitializeUserDetailsManagerConfigurer`类中)。
     * 所以系统自动提供的用户实际上相当于是全局Authentication Manager对应的用户。
     * 以上面的代码为例，当我们开始执行登录后，Spring Security首先会调用局部`AuthenticationManager`去进行登录校验，
     * 如果登录的用户名／密码是javaboy/123，那就直接登录成功，否则登录失败。当登录失败后，
     * 会继续调用局部AuthenticationManager的parent继续进行校验，
     * 此时如果登录的用户名／密码是user/cfc7f8b5-8346-492e-b25c-90c2c4501350，则登录成功，否则登录失败。
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //这段代码中，我们基于内存来管理用户，并向users中添加了一个用户，
        // 将配置好的users对象添加到HttpSecurity中，也就是配置到局部的AuthenticationManager中。
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        users.createUser(User.withUsername("javaboy").password("{noop}123").roles("admin").build());
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
//        users.createUser(User.withUsername("javaboy").password("{noop}123").roles("admin").build());
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
