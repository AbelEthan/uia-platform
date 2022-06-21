package com.uia.auth.config;

import com.uia.auth.security.config.FormIdentityLoginConfiguration;
import com.uia.auth.security.handler.CustomAccessDeniedHandler;
import com.uia.auth.security.handler.CustomAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @ClassName: {@link WebSecurityConfiguration}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/13 下午5:27
 * @Description
 */
@EnableWebSecurity
public class WebSecurityConfiguration {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .antMatchers("/oauth2/token/**", "/token/**").permitAll()
                                .anyRequest().authenticated()
                )
                .apply(new FormIdentityLoginConfiguration())
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()
                .and()
                .oauth2ResourceServer()
                .accessDeniedHandler(new CustomAccessDeniedHandler())
                .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                .jwt()
        ;
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/actuator/**", "/css/**", "/error");
    }

}