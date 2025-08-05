package hashsnap.login.controller;

import hashsnap.login.dto.SignupRequestDto;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 페이지 라우팅 컨트롤러
 * Thymeleaf 뷰 템플릿을 반환하는 페이지 네비게이션 담당
 * JWT 토큰 기반 클라이언트 사이드 라우팅 지원
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
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public String userPage() {
        return "userPage";
    }

    /**
     * 관리자 페이지 반환
     * @return admin.html
     */
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminPage() {
        return "admin";
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