package com.uia.auth.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.uia.auth.model.entity.Oauth2User;
import org.springframework.stereotype.Repository;

/**
 * Title: {@link Oauth2UserMapper}
 * Description: 账号信息 Mapper 接口
 *
 * @author AbelEthan
 * @email AbelEthan@aliyun.com
 * @date 2022-06-15 15:46:26
 */
@Repository
public interface Oauth2UserMapper extends BaseMapper<Oauth2User> {

}
