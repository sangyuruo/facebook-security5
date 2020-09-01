package sample.api.oauth;

import com.google.gson.Gson;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.client.endpoint.NimbusAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * @program: security-social-showcase
 * @description: 获取AccessToken
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-28 13:36
 **/
public class WxNimbusAuthorizationCodeTokenResponseClient extends NimbusAuthorizationCodeTokenResponseClient {
    static Logger LOG = LoggerFactory.getLogger(WxNimbusAuthorizationCodeTokenResponseClient.class);
    static Gson gson = new Gson();
    private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest)
            throws OAuth2AuthenticationException {
        LOG.info("in WxNimbusAuthorizationCodeTokenResponseClient.getTokenResponse .......................... ");
        ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();

        // Build the authorization code grant request for the token endpoint
        AuthorizationCode authorizationCode = new AuthorizationCode(
                authorizationGrantRequest.getAuthorizationExchange().getAuthorizationResponse().getCode());
        URI redirectUri = toURI(authorizationGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getRedirectUri());
        AuthorizationGrant authorizationCodeGrant = new AuthorizationCodeGrant(authorizationCode, redirectUri);
        URI tokenUri = toURI(clientRegistration.getProviderDetails().getTokenUri());

        // Set the credentials to authenticate the client at the token endpoint
        ClientID clientId = new ClientID(clientRegistration.getClientId());
        Secret clientSecret = new Secret(clientRegistration.getClientSecret());
        ClientAuthentication clientAuthentication;
        if (ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
            clientAuthentication = new ClientSecretPost(clientId, clientSecret);
        } else {
            clientAuthentication = new ClientSecretBasic(clientId, clientSecret);
        }

        com.nimbusds.oauth2.sdk.TokenResponse tokenResponse;
        try {
            // Send the Access Token request
            WxTokenRequest tokenRequest = new WxTokenRequest(tokenUri, clientAuthentication, authorizationCodeGrant);
            LOG.info("tokenRequest: " + gson.toJson(tokenRequest));
            HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
            LOG.info("httpRequest: " + gson.toJson(httpRequest));
            httpRequest.setAccept(MediaType.APPLICATION_JSON_VALUE);
            httpRequest.setConnectTimeout(30000);
            httpRequest.setReadTimeout(30000);
            /**
             * 取accessToken
             */
            HTTPResponse httpResponse = httpRequest.send();
            LOG.info("httpResponse: " + gson.toJson(httpResponse));
            tokenResponse = WxAccessTokenResponse.parse(httpResponse);
            LOG.info("tokenResponse: " + gson.toJson(httpResponse));
        } catch (ParseException pe) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "An error occurred parsing the Access Token response: " + pe.getMessage(), null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), pe);
        } catch (IOException ioe) {
            throw new AuthenticationServiceException("An error occurred while sending the Access Token Request: " +
                    ioe.getMessage(), ioe);
        }

        if (!tokenResponse.indicatesSuccess()) {
            TokenErrorResponse tokenErrorResponse = (TokenErrorResponse) tokenResponse;
            ErrorObject errorObject = tokenErrorResponse.getErrorObject();
            OAuth2Error oauth2Error = new OAuth2Error(errorObject.getCode(), errorObject.getDescription(),
                    (errorObject.getURI() != null ? errorObject.getURI().toString() : null));
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }

        WxAccessTokenResponse accessTokenResponse = (WxAccessTokenResponse) tokenResponse;
        WxAccessToken wxAccessToken = (WxAccessToken) accessTokenResponse.getTokens().getAccessToken();
        LOG.info("wxAccessToken: " + gson.toJson(wxAccessToken));
        String accessToken = wxAccessToken.getValue();
        OAuth2AccessToken.TokenType accessTokenType = null;
        if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(accessTokenResponse.getTokens().getAccessToken().getType().getValue())) {
            accessTokenType = OAuth2AccessToken.TokenType.BEARER;
        }
        long expiresIn = accessTokenResponse.getTokens().getAccessToken().getLifetime();

        // As per spec, in section 5.1 Successful Access Token Response
        // https://tools.ietf.org/html/rfc6749#section-5.1
        // If AccessTokenResponse.scope is empty, then default to the scope
        // originally requested by the client in the Authorization Request
        Set<String> scopes;
        if (CollectionUtils.isEmpty(accessTokenResponse.getTokens().getAccessToken().getScope())) {
            scopes = new LinkedHashSet<>(
                    authorizationGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getScopes());
        } else {
            scopes = new LinkedHashSet<>(
                    accessTokenResponse.getTokens().getAccessToken().getScope().toStringList());
        }

        Map<String, Object> additionalParameters = new LinkedHashMap<>(accessTokenResponse.getCustomParameters());
        additionalParameters.put("openid", wxAccessToken.getOpenid());
        OAuth2AccessTokenResponse oAuth2AccessTokenResponse =
                OAuth2AccessTokenResponse.withToken(accessToken)
                        .tokenType(accessTokenType)
                        .expiresIn(expiresIn)
                        .scopes(scopes)
                        .additionalParameters(additionalParameters)
                        .build();
        LOG.info("out WxNimbusAuthorizationCodeTokenResponseClient.getTokenResponse:" + gson.toJson(oAuth2AccessTokenResponse));
        return oAuth2AccessTokenResponse;
    }

    private static URI toURI(String uriStr) {
        try {
            return new URI(uriStr);
        } catch (Exception ex) {
            throw new IllegalArgumentException("An error occurred parsing URI: " + uriStr, ex);
        }
    }
}
