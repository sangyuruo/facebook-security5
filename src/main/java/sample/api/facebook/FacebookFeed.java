package sample.api.facebook;

import lombok.Data;
import sample.api.Feed;

import java.util.List;

@Data
public class FacebookFeed extends Feed {
    private List<FacebookPost> data;
}
