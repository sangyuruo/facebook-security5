package sample.api.oauth;

import com.google.gson.Gson;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-28 14:34
 **/
public class WxAccessToken extends BearerAccessToken {
    static Logger LOG = LoggerFactory.getLogger(WxAccessToken.class);
    static Gson gson = new Gson();
    String openid;

    public String getOpenid() {
        return openid;
    }

    public WxAccessToken(String accessTokenValue, long lifetime, Scope scope, String openid) {
        super(accessTokenValue, lifetime, scope);
        this.openid = openid;
    }

    @Override
    public String toAuthorizationHeader() {
        return "Bearer " + getValue();
    }

    /**
     * Parses a bearer access token from a JSON object access token
     * response.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The bearer access token.
     * @throws ParseException If the JSON object couldn't be parsed to a
     *                        bearer access token.
     */
    public static BearerAccessToken parse(final JSONObject jsonObject)
            throws ParseException {
        LOG.info("WxAccessToken.parse:" + gson.toJson(jsonObject));
        // Parse and verify type
//        AccessTokenType tokenType = new AccessTokenType(JSONObjectUtils.getString(jsonObject, "token_type"));

//        if (!tokenType.equals(AccessTokenType.BEARER))
//            throw new ParseException("Token type must be \"Bearer\"");
        // Parse value
        String accessTokenValue = JSONObjectUtils.getString(jsonObject, "access_token");
        LOG.info("accessTokenValue:" + accessTokenValue);

        // Parse lifetime
        long lifetime = 0;
        if (jsonObject.containsKey("expires_in")) {

            // Lifetime can be a JSON number or string
            if (jsonObject.get("expires_in") instanceof Number) {
                lifetime = JSONObjectUtils.getLong(jsonObject, "expires_in");
            } else {
                String lifetimeStr = JSONObjectUtils.getString(jsonObject, "expires_in");
                try {
                    lifetime = new Long(lifetimeStr);
                } catch (NumberFormatException e) {
                    throw new ParseException("Invalid \"expires_in\" parameter, must be integer");
                }
            }
        }
        // Parse scope
        Scope scope = null;

        if (jsonObject.containsKey("scope"))
            scope = Scope.parse(JSONObjectUtils.getString(jsonObject, "scope"));
        String openId = null;
        if (jsonObject.containsKey("openid")) {
            openId = JSONObjectUtils.getString(jsonObject, "openid");
        }
        return new WxAccessToken(accessTokenValue, lifetime, scope, openId);
    }
}
