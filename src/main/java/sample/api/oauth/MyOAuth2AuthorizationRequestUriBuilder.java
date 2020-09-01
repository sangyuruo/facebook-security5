package sample.api.oauth;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Set;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-25 17:57
 **/
public class MyOAuth2AuthorizationRequestUriBuilder {
    URI build(OAuth2AuthorizationRequest authorizationRequest) {
        Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");
        Set<String> scopes = authorizationRequest.getScopes();
        UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString(authorizationRequest.getAuthorizationUri())
                .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, authorizationRequest.getResponseType().getValue())
                .queryParam("appid", authorizationRequest.getClientId())
                .queryParam(OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(scopes, " "))
                .queryParam(OAuth2ParameterNames.STATE, authorizationRequest.getState());
        if (authorizationRequest.getRedirectUri() != null) {
            uriBuilder.queryParam(OAuth2ParameterNames.REDIRECT_URI, "http://www.yunxiangfu.life/login/oauth2/code/wechatmp");
//            uriBuilder.queryParam(OAuth2ParameterNames.REDIRECT_URI, authorizationRequest.getRedirectUri());
        }
        return uriBuilder.build().encode().toUri();
    }
}
