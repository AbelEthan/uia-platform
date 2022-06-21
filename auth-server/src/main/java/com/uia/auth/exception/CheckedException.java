package com.uia.auth.exception;

import lombok.NoArgsConstructor;

/**
 * @ClassName: {@link CheckedException}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/15 下午5:12
 * @Description
 */
@NoArgsConstructor
public class CheckedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public CheckedException(String message) {
        super(message);
    }

    public CheckedException(Throwable cause) {
        super(cause);
    }

    public CheckedException(String message, Throwable cause) {
        super(message, cause);
    }

    public CheckedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
