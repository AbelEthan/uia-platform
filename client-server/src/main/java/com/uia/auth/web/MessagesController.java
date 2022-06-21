package com.uia.auth.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @ClassName: {@link MessagesController}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/14 下午2:20
 * @Description
 */
@RestController
public class MessagesController {

    @GetMapping("/messages")
    public String[] getMessages() {
        return new String[] {"Message 1", "Message 2", "Message 3"};
    }
}