package com.uia.auth.security.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * @ClassName: {@link CustomUser}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/15 下午3:49
 * @Description
 */
public class CustomUser extends User implements OAuth2AuthenticatedPrincipal {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    @Getter
    @Setter
    private Long id;

    @Getter
    @Setter
    private Integer status;

    @Getter
    @Setter
    private Integer sex;

    public CustomUser(String username, String password, Integer status, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities, Long id, Integer sex) {
        super(username, password, status == 1, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.id = id;
        this.status = status;
        this.sex = sex;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return new HashMap<>();
    }

    @Override
    public String getName() {
        return this.getUsername();
    }
}
