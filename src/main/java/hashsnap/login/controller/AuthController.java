package hashsnap.login.controller;

import hashsnap.login.entity.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller // Thymeleaf 뷰 반환
public class AuthController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register(Model model) {
        model.addAttribute("user", new User()); // 빈 User 객체 추가
        return "register";
    }

    @GetMapping("/userPage")
    public String userPage() {
        return "userPage";
    }
}