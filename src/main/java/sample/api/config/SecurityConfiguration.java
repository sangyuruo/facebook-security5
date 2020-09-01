package sample.api.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.user.OAuth2User;
import sample.api.oauth.WxNimbusAuthorizationCodeTokenResponseClient;
import sample.api.oauth.WxOAuth2AuthorizationRequestRedirectFilter;
import sample.api.oauth.WxOAuth2LoginAuthenticationProvider;
import sample.api.oauth.WxOAuth2UserService;

/**
 * 支持微信的认证请求
 * 主要是修改请求参数
 */
@Configuration
@EnableWebSecurity(debug = true)
//@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    //WebSecurityConfigurerAdapter
    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfiguration.class);

    @Autowired
    ClientRegistrationRepository clientRegistrationRepository;

//    WxOAuth2AuthorizationRequestRedirectFilter wxOAuth2AuthorizationRequestRedirectFilter;

    public WxOAuth2AuthorizationRequestRedirectFilter wxOAuth2AuthorizationRequestRedirectFilter() {
        return new WxOAuth2AuthorizationRequestRedirectFilter(clientRegistrationRepository);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> oAuth2AccessTokenResponseClient = new WxNimbusAuthorizationCodeTokenResponseClient();
        OAuth2UserService<OAuth2UserRequest, OAuth2User> userService = new WxOAuth2UserService();

        ((HttpSecurity) ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl) http.authorizeRequests().
                anyRequest()).
                authenticated().
                /**
                 *  将wxOAuth2AuthorizationRequestRedirectFilter提前到 OAuth2AuthorizationRequestRedirectFilter之前执行
                 */
                        and().addFilterBefore(wxOAuth2AuthorizationRequestRedirectFilter(), OAuth2AuthorizationRequestRedirectFilter.class)).
                oauth2Login().
                tokenEndpoint().accessTokenResponseClient(oAuth2AccessTokenResponseClient)
                .and().
                userInfoEndpoint().userService(userService)
        ;
        http.authenticationProvider(new WxOAuth2LoginAuthenticationProvider(oAuth2AccessTokenResponseClient, userService));

//        .and().authenticationProvider(new WxOAuth2LoginAuthenticationProvider(oAuth2AccessTokenResponseClient,userService)).
        ;
//                and().userInfoEndpoint().
//        http.oauth2Login().tokenEndpoint().accessTokenResponseClient(new WxNimbusAuthorizationCodeTokenResponseClient());
    }

//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring()
//                .antMatchers("/**")
//                .antMatchers("/app/**/*.{js,html}")
//                .antMatchers("/i18n/**")
//                .antMatchers("/upload/**")
//                .antMatchers("/content/**")
//                .antMatchers("/test/**");
//    }


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .oauth2Login()
//                .authorizationEndpoint()
//                .authorizationRequestResolver(
//                        new CustomAuthorizationRequestResolver(
//                                this.clientRegistrationRepository));
//    }
}
