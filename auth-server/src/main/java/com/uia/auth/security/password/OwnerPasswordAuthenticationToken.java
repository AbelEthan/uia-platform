package com.uia.auth.security.password;

import com.uia.auth.security.base.AbstractBaseAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Map;
import java.util.Set;

/**
 * @ClassName: {@link OwnerPasswordAuthenticationToken}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/16 下午3:45
 * @Description 密码授权token信息
 */
public class OwnerPasswordAuthenticationToken extends AbstractBaseAuthenticationToken {
    public OwnerPasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType, Authentication clientPrincipal, Set<String> scopes, Map<String, Object> additionalParameters) {
        super(authorizationGrantType, clientPrincipal, scopes, additionalParameters);
    }
}
