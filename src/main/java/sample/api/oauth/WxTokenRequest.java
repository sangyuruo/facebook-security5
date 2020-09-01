package sample.api.oauth;

import com.google.gson.Gson;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Map;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-28 13:37
 **/
public class WxTokenRequest extends TokenRequest {
    static Logger LOG = LoggerFactory.getLogger(WxTokenRequest.class);
    static Gson gson = new Gson();
    /**
     * The authorisation grant.
     */
    private final AuthorizationGrant wxAuthzGrant;
//
//
//    /**
//     * The requested scope, {@code null} if not specified.
//     */
//    private final Scope scope;


    public WxTokenRequest(URI uri, ClientAuthentication clientAuth, AuthorizationGrant authzGrant, Scope scope) {
        super(uri, clientAuth, authzGrant, scope);
        this.wxAuthzGrant = authzGrant;
    }


    public WxTokenRequest(URI uri, ClientAuthentication clientAuth, AuthorizationGrant authzGrant) {
        super(uri, clientAuth, authzGrant);
        this.wxAuthzGrant = authzGrant;
    }

    @Override
    public HTTPRequest toHTTPRequest() {
        LOG.info("to WxTokenRequest.toHTTPRequest .............. ");
        if (getEndpointURI() == null)
            throw new SerializeException("The endpoint URI is not specified");
        URL url;

        try {
            url = getEndpointURI().toURL();
        } catch (MalformedURLException e) {
            throw new SerializeException(e.getMessage(), e);
        }

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, url);
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

        if (getClientAuthentication() != null) {
            getClientAuthentication().applyTo(httpRequest);
        }

        Map<String, String> params = httpRequest.getQueryParameters();
        LOG.info("params: " + gson.toJson(params));
        params.putAll(wxAuthzGrant.toParameters());
        LOG.info("params: " + gson.toJson(params));

        if (super.getScope() != null && !super.getScope().isEmpty()) {
            params.put("scope", super.getScope().toString());
        }

        if (getClientID() != null) {
            LOG.info("getClientID is not null");
            params.put("appid", getClientID().getValue());
            LOG.info("params: " + gson.toJson(params));
        }

        if (!getCustomParameters().isEmpty()) {
            params.putAll(getCustomParameters());
        }
        if (params.containsKey("client_id")) {
            String clientId = params.get("client_id");
            params.remove("client_id");
            params.put("appid", clientId);
        }
        if (params.containsKey("client_secret")) {
            String clientSecret = params.get("client_secret");
            params.remove("client_secret");
            params.put("secret", clientSecret);
        }

        LOG.info("params: " + gson.toJson(params));
        httpRequest.setQuery(URLUtils.serializeParameters(params));
        return httpRequest;
    }
}
