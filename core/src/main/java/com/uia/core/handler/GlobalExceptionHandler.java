package com.uia.core.handler;

import com.uia.core.model.ResponseResult;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * @ClassName: {@link GlobalExceptionHandler}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/15 下午2:18
 * @Description 全局错误处理器
 */
@Component
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseResult<String> exception(Exception e) {
        return ResponseResult.ok(e.getMessage());
    }
}
