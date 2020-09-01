package sample.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Component;
import sample.api.oauth.MyDefaultRedirectStrategy;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-25 17:12
 **/
@Configuration
@Component
public class OAuthConfig {
    @Bean
    public RedirectStrategy authorizationRedirectStrategy() {
        return new MyDefaultRedirectStrategy();
    }
}
