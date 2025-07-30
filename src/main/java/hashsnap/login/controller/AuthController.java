package hashsnap.login.controller;

import hashsnap.login.dto.SignupRequestDto;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller // Thymeleaf 뷰 반환
public class AuthController {

    @GetMapping("/")
    public String index() {
        return "redirect:/login"; // 루트 접속시 바로 로그인 페이지로
    }

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