package sample.api.oauth;

import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Map;

/**
 * @program: security-social-showcase
 * @description: 取用户信息请求对象
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-28 19:23
 **/
public class WxUserInfoRequest extends UserInfoRequest {
    String openid;

    public WxUserInfoRequest(URI uri, BearerAccessToken accessToken, String openid) {
        super(uri, accessToken);
        this.openid = openid;
    }

    @Override
    public HTTPRequest toHTTPRequest() {
        if (getEndpointURI() == null)
            throw new SerializeException("The endpoint URI is not specified");

        URL endpointURL;
        try {
            endpointURL = getEndpointURI().toURL();
        } catch (MalformedURLException e) {
            throw new SerializeException(e.getMessage(), e);
        }

        AccessToken wxAccessToken = getAccessToken();
        HTTPRequest httpRequest = new HTTPRequest(super.getMethod(), endpointURL);
        Map<String, String> params = httpRequest.getQueryParameters();
        params.put("openid", openid);
        params.put("access_token", wxAccessToken.getValue());
        params.put("lang", "zh_CN");
        httpRequest.setQuery(URLUtils.serializeParameters(params));
        return httpRequest;
    }
}
