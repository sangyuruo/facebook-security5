package sample.api.oauth;

import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-28 16:33
 **/
public class WxOAuth2UserService extends DefaultOAuth2UserService {
    static Logger LOG = LoggerFactory.getLogger(WxOAuth2UserService.class);
    Gson gson = new Gson();
    private static final String MISSING_USER_INFO_URI_ERROR_CODE = "missing_user_info_uri";
    private static final String MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute";
    private WxNimbusUserInfoResponseClient userInfoResponseClient = new WxNimbusUserInfoResponseClient();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        WxOAuth2UserRequest wxOAuth2UserRequest = null;
        if( userRequest instanceof  WxOAuth2UserRequest){
            wxOAuth2UserRequest = (WxOAuth2UserRequest) userRequest;
        }
        Assert.notNull(wxOAuth2UserRequest, "userRequest cannot be null");
        LOG.info("WxOAuth2UserService.loadUser:" + gson.toJson(wxOAuth2UserRequest));
        if (!StringUtils.hasText(wxOAuth2UserRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri())) {
            OAuth2Error oauth2Error = new OAuth2Error(
                    MISSING_USER_INFO_URI_ERROR_CODE,
                    "Missing required UserInfo Uri in UserInfoEndpoint for Client Registration: " +
                            wxOAuth2UserRequest.getClientRegistration().getRegistrationId(),
                    null
            );
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        if (!StringUtils.hasText(userNameAttributeName)) {
            OAuth2Error oauth2Error = new OAuth2Error(
                    MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE,
                    "Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: " +
                            wxOAuth2UserRequest.getClientRegistration().getRegistrationId(),
                    null
            );
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }

        ParameterizedTypeReference<Map<String, Object>> typeReference =
                new ParameterizedTypeReference<Map<String, Object>>() {
                };
        Map<String, Object> userAttributes = this.userInfoResponseClient.getUserInfoResponse(wxOAuth2UserRequest, typeReference);
        LOG.info("userAttributes:" + gson.toJson(userAttributes));
        GrantedAuthority authority = new OAuth2UserAuthority(userAttributes);
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(authority);

        return new DefaultOAuth2User(authorities, userAttributes, userNameAttributeName);
    }
}
