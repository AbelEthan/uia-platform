package com.uia.auth.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @ClassName: {@link AuthorizationController}
 * @Author AbelEthan
 * @Email AbelEthan@126.com
 * @Date 2022/6/14 下午2:00
 * @Description
 */
@RestController
public class AuthorizationController {
    private final WebClient webClient;
    private final String messagesBaseUri;

    public AuthorizationController(WebClient webClient, @Value("${messages.base-uri}") String messagesBaseUri) {
        this.webClient = webClient;
        this.messagesBaseUri = messagesBaseUri;
    }

    @GetMapping(value = "/authorize", params = "grant_type=authorization_code")
    public String[] authorizationCodeGrant(@RegisteredOAuth2AuthorizedClient("messaging-client-authorization-code")
                                                   OAuth2AuthorizedClient authorizedClient) {
        return this.webClient
                .get()
                .uri(this.messagesBaseUri)
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String[].class)
                .block();
    }

    // '/authorized' is the registered 'redirect_uri' for authorization_code
    @GetMapping(value = "/authorized", params = OAuth2ParameterNames.ERROR)
    public OAuth2Error authorizationFailed(Model model, HttpServletRequest request) {
        String errorCode = request.getParameter(OAuth2ParameterNames.ERROR);
        if (StringUtils.hasText(errorCode)) {
            return new OAuth2Error(
                    errorCode,
                    request.getParameter(OAuth2ParameterNames.ERROR_DESCRIPTION),
                    request.getParameter(OAuth2ParameterNames.ERROR_URI)
            );
        }
        return new OAuth2Error("Null");
    }

    @GetMapping(value = "/authorize", params = "grant_type=client_credentials")
    public String[] clientCredentialsGrant() {
        return this.webClient
                .get()
                .uri(this.messagesBaseUri)
                .attributes(clientRegistrationId("messaging-client-client-credentials"))
                .retrieve()
                .bodyToMono(String[].class)
                .block();
    }
}