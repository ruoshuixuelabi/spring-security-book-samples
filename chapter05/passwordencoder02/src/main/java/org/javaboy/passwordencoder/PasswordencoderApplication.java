package org.javaboy.passwordencoder;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@MapperScan("org.javaboy.passwordencoder.mapper")
public class PasswordencoderApplication {
    public static void main(String[] args) {
        SpringApplication.run(PasswordencoderApplication.class, args);
    }
}