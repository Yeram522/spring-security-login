package hashsnap.login.controller;

import hashsnap.login.dto.SignupRequestDto;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Thymeleaf 뷰 반환 페이지 컨트롤러
 */
@Controller
public class PageController {

    /**
     * 루트 접속 시 index.html을 반환하고, JavaScript가 토큰을 체크해서 리다이렉트 처리
     * @return index.html
     */
    @GetMapping("/")
    public String index() {
        return "index"; // index.html 반환 (JavaScript가 리다이렉트 처리)
    }

    /**
     * 로그인 페이지 반환
     * @return login.html
     */
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    /**
     * 회원가입 페이지 반환
     * @return register.html
     */
    @GetMapping("/register")
    public String registerForm(Model model) {
        model.addAttribute("user", new SignupRequestDto());
        return "register";
    }

    /**
     * 내 정보 조회 페이지 반환
     * @return userPage.html
     */
    @GetMapping("/userPage")
    public String userPage() {
        return "userPage";
    }

    /**
     * 비밀번호 찾기 페이지 반환
     * @return findPwd.html
     */
    @GetMapping("/findPwd")
    public String findPwd() {
        return "findPwd";
    }
}