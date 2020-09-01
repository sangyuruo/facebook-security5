package sample.api.oauth;

import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.time.Instant;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-28 19:56
 **/
public class WxOAuth2AccessToken extends OAuth2AccessToken {
    String openid;

    public WxOAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt, String openid) {
        super(tokenType, tokenValue, issuedAt, expiresAt);
        this.openid = openid;
    }

    public WxOAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt) {
        super(tokenType, tokenValue, issuedAt, expiresAt);
    }

    public String getOpenid() {
        return openid;
    }
}
