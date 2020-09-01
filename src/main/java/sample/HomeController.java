package sample;

import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import sample.api.ApiBinding;

@Controller
public class HomeController {

    private ApiBinding apiBinding;
    private static Gson gson = new Gson();

    @Autowired
    public HomeController(ApiBinding apiBinding) {
        this.apiBinding = apiBinding;
    }

    @GetMapping("/")
    public String home(Model model) {
        String profile = gson.toJson(apiBinding.getProfile());
        System.out.println(profile);

        model.addAttribute("profile", apiBinding.getProfile());
        model.addAttribute("feed", apiBinding.getFeed());
        return "home";
    }

}
