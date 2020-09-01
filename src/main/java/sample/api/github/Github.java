package sample.api.github;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import sample.api.ApiBinding;
import sample.api.facebook.Profile;

import java.io.IOException;
import java.util.List;

public class Github extends ApiBinding<GithubFeed> {

    //	https://api.github.com/user
//	private static final String GRAPH_API_BASE_URL = "https://graph.facebook.com/v2.12";
    private static final String API_BASE_URL = "https://api.github.com";

    public Github(String accessToken) {
        super(accessToken);
    }

    @Override
    public Profile getProfile() {
        return restTemplate.getForObject(API_BASE_URL + "/user", Profile.class);
    }

    @Override
    public GithubFeed getFeed() {
        return restTemplate.getForObject(API_BASE_URL + "/feeds", GithubFeed.class);
    }

    ClientHttpRequestInterceptor getBearerTokenInterceptor(String accessToken) {
        return new ClientHttpRequestInterceptor() {
            @Override
            public ClientHttpResponse intercept(HttpRequest request, byte[] bytes, ClientHttpRequestExecution execution) throws IOException {
                request.getHeaders().add("Authorization", "token " + accessToken);
                return execution.execute(request, bytes);
            }
        };
    }

}
