package com.uia.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @ClassName: {@link DefaultSecurityConfig}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/13 下午5:27
 * @Description
 */
@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/webjars/**");
    }

    // @formatter:off
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .mvcMatchers("/messages/**").access("hasAuthority('message.read')")
                                .anyRequest().authenticated()
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login.loginPage("/oauth2/authorization/messaging-client-oidc")
                )
                .oauth2Client(Customizer.withDefaults())
                .oauth2ResourceServer()
                .jwt()
        ;
        return http.build();
    }
    // @formatter:on

}