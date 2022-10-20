package org.javaboy.formlogin;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

import java.util.HashMap;
import java.util.Map;

/**
 * 新版本里面 WebSecurityConfigurerAdapter 这个类已经被废弃了，推荐使用
 *
 * @deprecated Use a {@link org.springframework.security.web.SecurityFilterChain} Bean to
 * configure {@link HttpSecurity} or a {@link WebSecurityCustomizer} Bean to configure
 */
@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //authorizeRequests()方法表示开启权限配置
        return http.authorizeRequests()
                //.anyRequest().authenticated()表示所有的请求都要认证之后才能访问
                .anyRequest().authenticated()
                //and()方法会返回HttpSecurityBuilder对象的一个子类(实际上就是HttpSecurity)，
                // 所以and()方法相当于又回到HttpSecurity实例，重新开启新一轮的配置
                .and()
                //formLogin()表示开启表单登录配置
                .formLogin()
                //loginPage用来配置登录页面地址
                .loginPage("/mylogin.html")
                //loginProcessingUrl用来配置登录接口地址
                .loginProcessingUrl("/doLogin")
                //defaultSuccessUrl表示登录成功后的跳转地址
                .defaultSuccessUrl("/index.html")
                //successForwardUrl也可以实现登录成功后的跳转
                //failureUrl表示登录失败后的跳转地址
                .failureHandler(new MyAuthenticationFailureHandler())
                //usernameParameter表示登录用户名的参数名称
                .usernameParameter("uname")
                //passwordParameter表示登录密码的参数名称
                .passwordParameter("passwd")
                //permitAll表示跟登录相关的页面和接口不做拦截，直接通过
                .permitAll()
                .and()
                .logout()
                .logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/logout1", "GET"),
                        new AntPathRequestMatcher("/logout2", "POST")))
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .defaultLogoutSuccessHandlerFor((req, resp, auth) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    Map<String, Object> result = new HashMap<>();
                    result.put("status", 200);
                    result.put("msg", "使用 logout1 注销成功!");
                    ObjectMapper om = new ObjectMapper();
                    String s = om.writeValueAsString(result);
                    resp.getWriter().write(s);
                }, new AntPathRequestMatcher("/logout1", "GET"))
                .defaultLogoutSuccessHandlerFor((req, resp, auth) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    Map<String, Object> result = new HashMap<>();
                    result.put("status", 200);
                    result.put("msg", "使用 logout2 注销成功!");
                    ObjectMapper om = new ObjectMapper();
                    String s = om.writeValueAsString(result);
                    resp.getWriter().write(s);
                }, new AntPathRequestMatcher("/logout2", "POST"))
                .and()
                .csrf().disable()
                .build();
    }
}