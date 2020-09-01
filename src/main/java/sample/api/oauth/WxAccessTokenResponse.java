package sample.api.oauth;

import com.google.gson.Gson;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-28 14:19
 **/
public class WxAccessTokenResponse extends AccessTokenResponse {
    static Logger LOG = LoggerFactory.getLogger(WxAccessTokenResponse.class);
    static Gson gson = new Gson();

    public WxAccessTokenResponse(Tokens tokens) {
        super(tokens);
    }

    public WxAccessTokenResponse(Tokens tokens, Map<String, Object> customParams) {
        super(tokens, customParams);
    }

    public static WxAccessTokenResponse parse(final HTTPResponse httpResponse)
            throws ParseException {
        LOG.info("WxAccessTokenResponse.parse(HTTPResponse) ................. " + gson.toJson(httpResponse));
        httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
        String content = httpResponse.getContent();
        JSONObject jsonObject = JSONObjectUtils.parse(content);
        LOG.info("jsonObject:" + gson.toJson(jsonObject));
//        JSONObject jsonObject = httpResponse.getContentAsJSONObject();
        return parse(jsonObject);
    }

    public static WxAccessTokenResponse parse(final JSONObject jsonObject)
            throws ParseException {
        LOG.info("WxAccessTokenResponse.parse(JSONObject) ................. " + gson.toJson(jsonObject));
        Tokens tokens = WxTokens.parse(jsonObject);
        // Determine the custom param names
        Set<String> customParamNames = new HashSet<>();
        customParamNames.addAll(jsonObject.keySet());
        customParamNames.removeAll(tokens.getParameterNames());

        Map<String, Object> customParams = null;
        if (!customParamNames.isEmpty()) {
            customParams = new HashMap<>();
            for (String name : customParamNames) {
                customParams.put(name, jsonObject.get(name));
            }
        }

        return new WxAccessTokenResponse(tokens, customParams);
    }
}
