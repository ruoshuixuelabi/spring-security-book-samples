package org.javaboy.formlogin.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

/**
 * @author 江南一点雨
 * @微信公众号 江南一点雨
 * @网站 http://www.itboyhub.com
 * @国际站 http://www.javaboy.org
 * @微信 a_java_boy
 * @GitHub https://github.com/lenve
 * @Gitee https://gitee.com/lenve
 */
@RestController
public class UserController {
    @GetMapping("/user")
    public void userInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String name = authentication.getName();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println("name = " + name);
        System.out.println("authorities = " + authorities);
        new Thread(() -> {
            Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
            if (authentication1 == null) {
                System.out.println("获取用户信息失败");
                return;
            }
            String name1 = authentication1.getName();
            Collection<? extends GrantedAuthority> authorities1 = authentication1.getAuthorities();
            String threadName = Thread.currentThread().getName();
            System.out.println(threadName + ":name = " + name1);
            System.out.println(threadName + ":authorities = " + authorities1);
        }).start();
    }
}
