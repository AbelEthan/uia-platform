package com.uia.auth.web;

import com.uia.core.model.ResponseResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ClassName: {@link TestController}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/15 下午3:08
 * @Description
 */
@RestController
public class TestController {

    @GetMapping("/test")
    public ResponseResult test() {
        return ResponseResult.ok("xixixix");
    }
}
