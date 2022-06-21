package com.uia.auth.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.uia.auth.security.model.CustomUser;
import com.uia.auth.model.entity.Oauth2User;
import org.springframework.core.Ordered;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Title: {@link Oauth2UserService }
 * Description: 账号信息 服务类
 *
 * @author AbelEthan
 * @email AbelEthan@126.com
 * @date 2022-06-15 15:46:26
 */
public interface Oauth2UserService extends IService<Oauth2User>, UserDetailsService, Ordered {

    /**
     * 是否支持此客户端校验
     * @param clientId 目标客户端
     * @return true/false
     */
    default boolean support(String clientId, String grantType) {
        return true;
    }

    /**
     * 排序值 默认取最大的
     * @return 排序值
     */
    default int getOrder() {
        return 0;
    }

    /**
     * 构建userdetails
     * @param result 用户信息
     * @return UserDetails
     */
    default UserDetails getUserDetails(Oauth2User info) {
        if (info == null) {
            throw new UsernameNotFoundException("用户不存在");
        }

        Set<String> dbAuthsSet = new HashSet<>();

//        if (ArrayUtil.isNotEmpty(info.getRoles())) {
//            // 获取角色
//            Arrays.stream(info.getRoles()).forEach(role -> dbAuthsSet.add(SecurityConstants.ROLE + role));
//            // 获取资源
//            dbAuthsSet.addAll(Arrays.asList(info.getPermissions()));
//
//        }

        Collection<GrantedAuthority> authorities = AuthorityUtils
                .createAuthorityList(dbAuthsSet.toArray(new String[0]));
//        SysUser user = info.getSysUser();

        // 构造security用户
        return new CustomUser(info.getUsername(), "{bcrypt}" + info.getPassword(), info.getStatus(), true, true, true, authorities, info.getId(), info.getSex());
    }

    /**
     * 通过用户实体查询
     * @param simpleUser user
     * @return
     */
    default UserDetails loadUserByUser(CustomUser simpleUser) {
        return this.loadUserByUsername(simpleUser.getUsername());
    }

}
