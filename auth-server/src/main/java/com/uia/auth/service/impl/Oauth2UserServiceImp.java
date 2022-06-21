package com.uia.auth.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.uia.auth.model.entity.Oauth2User;
import com.uia.auth.mapper.Oauth2UserMapper;
import com.uia.auth.service.Oauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Title: {@link Oauth2UserServiceImp }
 * Description: 账号信息 服务实现类
 *
 * @author AbelEthan
 * @email AbelEthan@126.com
 * @date 2022-06-15 15:46:26
 */
@Service
public class Oauth2UserServiceImp extends ServiceImpl<Oauth2UserMapper, Oauth2User> implements Oauth2UserService {

    @Autowired
    private Oauth2UserMapper targetMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        QueryWrapper<Oauth2User> queryWrapper = new QueryWrapper<>();
        queryWrapper.lambda().eq(Oauth2User::getUsername, username);
        Oauth2User oauth2User = targetMapper.selectOne(queryWrapper);
        UserDetails userDetails = getUserDetails(oauth2User);
        return userDetails;
    }

    @Override
    public int getOrder() {
        return Integer.MIN_VALUE;
    }
}
