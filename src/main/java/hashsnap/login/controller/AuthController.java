package hashsnap.login.controller;

import hashsnap.login.dto.SignupRequestDto;
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
    public String registerForm(Model model) {
        model.addAttribute("user", new SignupRequestDto());
        return "register";
    }

    @GetMapping("/userPage")
    public String userPage() {
        return "userPage";
    }
}