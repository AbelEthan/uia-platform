package com.uia.core.constants;

/**
 * @author jumuning
 * @description OAuth2 异常信息
 */
public class OAuth2ErrorCodeConstant {

	/** 用户名未找到 */
	public final static String USERNAME_NOT_FOUND = "username_not_found";

	/** 错误凭证 */
	public final static String BAD_CREDENTIALS = "bad_credentials";

	/** 用户被锁 */
	public final static String USER_LOCKED = "user_locked";

	/** 用户禁用 */
	public final static String USER_DISABLE = "user_disable";

	/** 用户过期 */
	public final static String USER_EXPIRED = "user_expired";

	/** 证书过期 */
	public final static String CREDENTIALS_EXPIRED = "credentials_expired";

	/** scope 为空异常 */
	public final static String SCOPE_IS_EMPTY = "scope_is_empty";

	/**
	 * 令牌不存在
	 */
	public final static String TOKEN_MISSING = "token_missing";

	/** 未知的登录异常 */
	public final static String UN_KNOW_LOGIN_ERROR = "un_know_login_error";

}
