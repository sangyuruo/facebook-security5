package sample.api.oauth;

import com.google.gson.Gson;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @program: security-social-showcase
 * @description:
 * @author: sangjun 58839016@qq.com
 * @create: 2020-08-28 14:33
 **/
public class WxTokens extends Tokens {
    static Logger LOG = LoggerFactory.getLogger(WxAccessToken.class);
    static Gson gson = new Gson();

    /**
     * Creates a new tokens instance.
     *
     * @param accessToken  The access token. Must not be {@code null}.
     * @param refreshToken The refresh token. If none {@code null}.
     */
    public WxTokens(AccessToken accessToken, RefreshToken refreshToken) {
        super(accessToken, refreshToken);
    }

    public static Tokens parse(final JSONObject jsonObject)
            throws ParseException {
        LOG.info("WxTokens.parse:" + gson.toJson(jsonObject));
        BearerAccessToken accessToken = WxAccessToken.parse(jsonObject);
        LOG.info("accessToken:" + gson.toJson(accessToken));
        RefreshToken refreshToken = RefreshToken.parse(jsonObject);
        LOG.info("refreshToken:" + gson.toJson(refreshToken));
        return new Tokens(accessToken, refreshToken);
    }
}
