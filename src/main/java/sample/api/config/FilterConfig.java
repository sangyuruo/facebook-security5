package sample.api.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import sample.api.oauth.WxOAuth2AuthorizationRequestRedirectFilter;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-26 09:20
 **/
//@Configuration
public class FilterConfig {
    @Bean
    public FilterRegistrationBean filterRegistration() {
        // 新建过滤器注册类
        FilterRegistrationBean registration = new FilterRegistrationBean();
        // 添加自定义 过滤器
        registration.setFilter(wxOAuth2AuthorizationRequestRedirectFilter());
        // 设置过滤器的URL模式
        registration.addUrlPatterns("/*");
        //设置过滤器顺序
        registration.setOrder(1);
        return registration;
    }

    @Bean
    public WxOAuth2AuthorizationRequestRedirectFilter wxOAuth2AuthorizationRequestRedirectFilter() {
        return new WxOAuth2AuthorizationRequestRedirectFilter(null);
    }
}
