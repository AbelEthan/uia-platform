package com.uia.auth.security.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.TypeAlias;

import java.time.Instant;

/**
 * @ClassName: {@link CustomAuthorization}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/21 上午11:32
 * @Description
 */
@TypeAlias("CustomAuthorization")
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CustomAuthorization {
    @Id
    private String id;
    private String registeredClientId;
    private String principalName;
    private String authorizationGrantType;
    private String attributes;
    private String state;
    private String authorizationCode;
    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;
    private String authorizationCodeMetadata;
    private String accessToken;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;
    private String accessTokenMetadata;
    private String accessTokenScopes;
    private String refreshToken;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;
    private String refreshTokenMetadata;
    private String idToken;
    private Instant idTokenIssuedAt;
    private Instant idTokenExpiresAt;
    private String idTokenMetadata;
    private String idTokenClaims;
}
