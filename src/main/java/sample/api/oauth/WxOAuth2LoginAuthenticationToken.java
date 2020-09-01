package sample.api.oauth;

import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-28 20:01
 **/
public class WxOAuth2LoginAuthenticationToken extends OAuth2LoginAuthenticationToken {
    public WxOAuth2LoginAuthenticationToken(ClientRegistration clientRegistration, OAuth2AuthorizationExchange authorizationExchange) {
        super(clientRegistration, authorizationExchange);
    }
}
