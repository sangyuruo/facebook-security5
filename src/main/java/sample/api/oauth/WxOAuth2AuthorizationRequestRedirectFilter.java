package sample.api.oauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-25 17:53
 * <code>OAuth2AuthorizationRequestRedirectFilter</code>
 **/
@WebFilter
public class WxOAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {
    /**
     * The default base {@code URI} used for authorization requests.
     */
    public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private final AntPathRequestMatcher authorizationRequestMatcher;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final MyOAuth2AuthorizationRequestUriBuilder authorizationRequestUriBuilder = new MyOAuth2AuthorizationRequestUriBuilder();
    private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();
    private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
            new HttpSessionOAuth2AuthorizationRequestRepository();

    static Logger LOG = LoggerFactory.getLogger(WxOAuth2AuthorizationRequestRedirectFilter.class);
    /**
     * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
     *
     * @param clientRegistrationRepository the repository of client registrations
     */
    public WxOAuth2AuthorizationRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository) {
        this(clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }

    /**
     * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
     *
     * @param clientRegistrationRepository the repository of client registrations
     * @param authorizationRequestBaseUri  the base {@code URI} used for authorization requests
     */
    public WxOAuth2AuthorizationRequestRedirectFilter(
            ClientRegistrationRepository clientRegistrationRepository, String authorizationRequestBaseUri) {

        Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        this.authorizationRequestMatcher = new AntPathRequestMatcher(
                authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    /**
     * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
     *
     * @param authorizationRequestRepository the repository used for storing {@link OAuth2AuthorizationRequest}'s
     */
    public final void setAuthorizationRequestRepository(AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
        Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
        this.authorizationRequestRepository = authorizationRequestRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (this.shouldRequestAuthorization(request, response)) {
            try {
                this.sendRedirectForAuthorization(request, response);
            } catch (Exception failed) {
                this.unsuccessfulRedirectForAuthorization(request, response, failed);
            }
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean shouldRequestAuthorization(HttpServletRequest request, HttpServletResponse response) {
        boolean should = false;
        if (this.authorizationRequestMatcher.matches(request)) {
            String registrationId = this.authorizationRequestMatcher
                    .extractUriTemplateVariables(request).get(REGISTRATION_ID_URI_VARIABLE_NAME);
            ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
            if (clientRegistration == null) {
                should = false;
            } else {
                if (registrationId.equals("wechatmp") || registrationId.equals("wechat")) {
                    should = true;
                }
            }
        }
        return should;
//        return this.authorizationRequestMatcher.matches(request);
    }

    private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        String registrationId = this.authorizationRequestMatcher
                .extractUriTemplateVariables(request).get(REGISTRATION_ID_URI_VARIABLE_NAME);
        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
        if (clientRegistration == null) {
            throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
        }

        String redirectUriStr = this.expandRedirectUri(request, clientRegistration);

        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());

        OAuth2AuthorizationRequest.Builder builder;
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
            builder = OAuth2AuthorizationRequest.authorizationCode();
        } else if (AuthorizationGrantType.IMPLICIT.equals(clientRegistration.getAuthorizationGrantType())) {
            builder = OAuth2AuthorizationRequest.implicit();
        } else {
            throw new IllegalArgumentException("Invalid Authorization Grant Type for Client Registration (" +
                    clientRegistration.getRegistrationId() + "): " + clientRegistration.getAuthorizationGrantType());
        }
        OAuth2AuthorizationRequest authorizationRequest = builder
                .clientId(clientRegistration.getClientId())
                .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
                .redirectUri(redirectUriStr)
                .scopes(clientRegistration.getScopes())
                .state(this.stateGenerator.generateKey())
                .additionalParameters(additionalParameters)
                .build();

        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
            this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
        }

        URI redirectUri = this.authorizationRequestUriBuilder.build(authorizationRequest);
        LOG.info("redirectUri:" + redirectUri.toString());
        this.authorizationRedirectStrategy.sendRedirect(request, response, redirectUri.toString());
    }

    private void unsuccessfulRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
                                                      Exception failed) throws IOException, ServletException {

        if (logger.isDebugEnabled()) {
            logger.debug("Authorization Request failed: " + failed.toString(), failed);
        }
        response.sendError(HttpStatus.BAD_REQUEST.value(), HttpStatus.BAD_REQUEST.getReasonPhrase());
    }

    private String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration) {
        int port = request.getServerPort();
        if (("http".equals(request.getScheme()) && port == 80) || ("https".equals(request.getScheme()) && port == 443)) {
            port = -1;        // Removes the port in UriComponentsBuilder
        }

        String baseUrl = UriComponentsBuilder.newInstance()
                .scheme(request.getScheme())
                .host(request.getServerName())
                .port(port)
                .path(request.getContextPath())
                .build()
                .toUriString();

        Map<String, String> uriVariables = new HashMap<>();
        uriVariables.put("baseUrl", baseUrl);
        uriVariables.put("registrationId", clientRegistration.getRegistrationId());

        return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
                .buildAndExpand(uriVariables)
                .toUriString();
    }
}
