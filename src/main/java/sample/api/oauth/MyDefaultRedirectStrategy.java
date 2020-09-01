package sample.api.oauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.DefaultRedirectStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-25 17:07
 **/
public class MyDefaultRedirectStrategy extends DefaultRedirectStrategy {
    static Logger LOG = LoggerFactory.getLogger(MyDefaultRedirectStrategy.class);

    @Override
    public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
        LOG.info("sendRedirect: " + url);
        String redirectUrl = this.calculateRedirectUrl(request.getContextPath(), url);
        LOG.info("calculateRedirectUrl: " + redirectUrl);
        redirectUrl = response.encodeRedirectURL(redirectUrl);
        LOG.info("encodeRedirectURL: " + redirectUrl);
        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Redirecting to '" + redirectUrl + "'");
        }

        response.sendRedirect(redirectUrl);
    }
}
