package sample.api.facebook;

import sample.api.ApiBinding;

public class Facebook extends ApiBinding<FacebookFeed> {

    private static final String GRAPH_API_BASE_URL = "https://graph.facebook.com/v2.12";

    public Facebook(String accessToken) {
        super(accessToken);
    }

    @Override
    public Profile getProfile() {
        return restTemplate.getForObject(GRAPH_API_BASE_URL + "/me", Profile.class);
    }

    @Override
    public FacebookFeed getFeed() {
        return restTemplate.getForObject(GRAPH_API_BASE_URL + "/me/feed", FacebookFeed.class);
    }

}
