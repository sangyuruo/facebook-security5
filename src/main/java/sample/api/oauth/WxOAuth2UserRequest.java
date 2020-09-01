package sample.api.oauth;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-29 08:52
 **/
public class WxOAuth2UserRequest extends OAuth2UserRequest {
    String openid;

    /**
     * Constructs an {@code OAuth2UserRequest} using the provided parameters.
     *
     * @param clientRegistration the client registration
     * @param accessToken        the access token
     */
    public WxOAuth2UserRequest(ClientRegistration clientRegistration, OAuth2AccessToken accessToken, String openid) {
        super(clientRegistration, accessToken);
        this.openid = openid;
    }

    public String getOpenid() {
        return openid;
    }
}
