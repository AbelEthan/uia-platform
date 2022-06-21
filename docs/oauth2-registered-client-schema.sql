create table oauth2_registered_client
(
    id                            bigint auto_increment comment '注册应用ID'
        primary key,
    client_id                     varchar(32)                         not null comment '应用ID',
    client_id_issued_at           timestamp default CURRENT_TIMESTAMP not null comment '应用发布时间',
    client_secret                 varchar(64) null comment '应用秘钥',
    client_secret_expires_at      datetime null comment '秘钥到期时间',
    client_name                   varchar(32)                         not null comment '应用名',
    client_authentication_methods varchar(1000)                       not null comment '应用身份验证方法',
    authorization_grant_types     varchar(1000)                       not null comment '授权授予类型',
    redirect_uris                 varchar(1000) null comment '重定向URI',
    scopes                        varchar(1000)                       not null comment '权限范围',
    client_settings               varchar(2000)                       not null comment '应用设置',
    token_settings                varchar(2000)                       not null comment 'token设置'
) comment '应用注册表';

