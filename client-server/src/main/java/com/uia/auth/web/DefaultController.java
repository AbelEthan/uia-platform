package com.uia.auth.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @ClassName: {@link DefaultController}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/14 下午2:00
 * @Description
 */
@Controller
public class DefaultController {

    @GetMapping("/")
    public String root() {
        return "redirect:/index";
    }

    @GetMapping("/index")
    public String index() {
        return "index";
    }
}
