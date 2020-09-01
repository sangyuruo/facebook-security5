package sample.api.oauth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-28 19:39
 **/
public class WxOAuth2LoginAuthenticationProvider implements AuthenticationProvider {
    private static final String INVALID_STATE_PARAMETER_ERROR_CODE = "invalid_state_parameter";
    private static final String INVALID_REDIRECT_URI_PARAMETER_ERROR_CODE = "invalid_redirect_uri_parameter";
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
    private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

    /**
     * Constructs an {@code OAuth2LoginAuthenticationProvider} using the provided parameters.
     *
     * @param accessTokenResponseClient the client used for requesting the access token credential from the Token Endpoint
     * @param userService               the service used for obtaining the user attributes of the End-User from the UserInfo Endpoint
     */
    public WxOAuth2LoginAuthenticationProvider(
            OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
            OAuth2UserService<OAuth2UserRequest, OAuth2User> userService) {

        Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
        Assert.notNull(userService, "userService cannot be null");
        this.accessTokenResponseClient = accessTokenResponseClient;
        this.userService = userService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2LoginAuthenticationToken authorizationCodeAuthentication =
                (OAuth2LoginAuthenticationToken) authentication;

        // Section 3.1.2.1 Authentication Request - http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // scope
        // 		REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
        if (authorizationCodeAuthentication.getAuthorizationExchange()
                .getAuthorizationRequest().getScopes().contains("openid")) {
            // This is an OpenID Connect Authentication Request so return null
            // and let OidcAuthorizationCodeAuthenticationProvider handle it instead
            return null;
        }

        OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication
                .getAuthorizationExchange().getAuthorizationRequest();
        OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication
                .getAuthorizationExchange().getAuthorizationResponse();

        if (authorizationResponse.statusError()) {
            throw new OAuth2AuthenticationException(
                    authorizationResponse.getError(), authorizationResponse.getError().toString());
        }

        if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_STATE_PARAMETER_ERROR_CODE);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }

        if (!authorizationResponse.getRedirectUri().equals(authorizationRequest.getRedirectUri())) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_REDIRECT_URI_PARAMETER_ERROR_CODE);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }

        OAuth2AccessTokenResponse accessTokenResponse =
                this.accessTokenResponseClient.getTokenResponse(
                        new OAuth2AuthorizationCodeGrantRequest(
                                authorizationCodeAuthentication.getClientRegistration(),
                                authorizationCodeAuthentication.getAuthorizationExchange()));

        OAuth2AccessToken accessToken = accessTokenResponse.getAccessToken();
        String openid = (String) accessTokenResponse.getAdditionalParameters().get("openid");

        OAuth2User oauth2User = this.userService.loadUser(
                new WxOAuth2UserRequest(authorizationCodeAuthentication.getClientRegistration(), accessToken, openid));

        Collection<? extends GrantedAuthority> mappedAuthorities =
                this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

        OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(
                authorizationCodeAuthentication.getClientRegistration(),
                authorizationCodeAuthentication.getAuthorizationExchange(),
                oauth2User,
                mappedAuthorities,
                accessToken);
        authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());

        return authenticationResult;
    }

    /**
     * Sets the {@link GrantedAuthoritiesMapper} used for mapping {@link OAuth2User#getAuthorities()}
     * to a new set of authorities which will be associated to the {@link OAuth2LoginAuthenticationToken}.
     *
     * @param authoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the user's authorities
     */
    public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
        this.authoritiesMapper = authoritiesMapper;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2LoginAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
