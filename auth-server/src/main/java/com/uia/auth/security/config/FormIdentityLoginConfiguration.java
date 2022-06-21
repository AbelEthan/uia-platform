package com.uia.auth.security.config;

import com.uia.auth.security.handler.FormAuthenticationFailureHandler;
import com.uia.auth.security.handler.SsoLogoutSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * @ClassName: {@link FormIdentityLoginConfiguration}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/15 下午5:06
 * @Description
 */
public class FormIdentityLoginConfiguration extends AbstractHttpConfigurer<FormIdentityLoginConfiguration, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) throws Exception {
        http
                .formLogin(formLogin -> {
                    formLogin.loginPage("/token/login");
                    formLogin.loginProcessingUrl("/token/form");
                    formLogin.failureHandler(new FormAuthenticationFailureHandler());

                })
                .logout() // SSO登出成功处理
                .logoutSuccessHandler(new SsoLogoutSuccessHandler())
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true).and().csrf().disable();
    }
}
