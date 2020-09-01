package sample.api.config;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import javax.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-26 21:56
 **/
public class CustomAuthorizationRequestResolver {
//implements OAuth2AuthorizationRequestResolver {
//    private final OAuth2AuthorizationRequestResolver defaultAuthorizationRequestResolver;
//
//    public CustomAuthorizationRequestResolver(
//            ClientRegistrationRepository clientRegistrationRepository) {
//
//        this.defaultAuthorizationRequestResolver =
//                new DefaultOAuth2AuthorizationRequestResolver(
//                        clientRegistrationRepository, "/oauth2/authorization");
//    }
//
//    @Override
//    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
//        OAuth2AuthorizationRequest authorizationRequest =
//                this.defaultAuthorizationRequestResolver.resolve(request);
//        2
//
//        return authorizationRequest != null ? 3
//        customAuthorizationRequest(authorizationRequest) :
//        null;
//    }
//
//    @Override
//    public OAuth2AuthorizationRequest resolve(
//            HttpServletRequest request, String clientRegistrationId) {
//
//        OAuth2AuthorizationRequest authorizationRequest =
//                this.defaultAuthorizationRequestResolver.resolve(
//                        request, clientRegistrationId);
//
//        return authorizationRequest != null ? customAuthorizationRequest(authorizationRequest) : null;
//    }
//
//    private OAuth2AuthorizationRequest customAuthorizationRequest(
//            OAuth2AuthorizationRequest authorizationRequest) {
//
//        Map<String, Object> additionalParameters =
//                new LinkedHashMap<>(authorizationRequest.getAdditionalParameters());
//        additionalParameters.put("prompt", "consent");
//
//        return OAuth2AuthorizationRequest.from(authorizationRequest)
//                .additionalParameters(additionalParameters)
//                .build();
//    }
}

