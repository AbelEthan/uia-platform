package com.uia.auth;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

/**
 * @ClassName: {@link AuthServerApplication}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/13 下午5:29
 * @Description
 */
@MapperScan("com.uia.auth.mapper")
@ComponentScan(basePackages = {"com.uia.auth", "com.uia.core"})
@SpringBootApplication
public class AuthServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }
}
