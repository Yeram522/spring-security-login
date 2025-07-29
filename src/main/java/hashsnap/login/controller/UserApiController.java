package hashsnap.login.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController  // JSON 반환
@RequestMapping("/api")
public class UserApiController {

    @GetMapping("/users")
    public ResponseEntity<Map<String, Object>> checkEmailDuplicate(@RequestParam String email) {
        Map<String, Object> response = new HashMap<>();
        response.put("exists", false);
        response.put("success", true);
        response.put("message", "사용 가능한 이메일입니다.");

        return ResponseEntity.ok(response);
    }

    @PostMapping("/users")
    public ResponseEntity<Map<String, Object>> registerUser(@RequestBody Map<String, String> userData) {
        Map<String, Object> response = new HashMap<>();

        System.out.println("회원가입 요청: " + userData);

        // 더미 응답 (실제로는 DB 저장 로직)
        response.put("success", true);
        response.put("message", "회원가입이 완료되었습니다.");

        return ResponseEntity.ok(response);
    }

    @PostMapping("/email-verification")
    public ResponseEntity<Map<String, Object>> handleEmailVerification(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        String action = request.get("action");
        String email = request.get("email");

        if ("send".equals(action)) {
            // 인증번호 발송 처리
            System.out.println("인증번호 발송 요청: " + email);

            response.put("success", true);
            response.put("message", "인증번호가 발송되었습니다.");

        } else if ("verify".equals(action)) {
            // 인증번호 확인 처리
            String verificationCode = request.get("verificationCode");
            System.out.println("인증번호 확인 요청: " + email + ", 코드: " + verificationCode);

            // 더미 데이터: "123456"이면 성공, 아니면 실패
            if ("123456".equals(verificationCode)) {
                response.put("success", true);
                response.put("message", "이메일 인증이 완료되었습니다.");
            } else {
                response.put("success", false);
                response.put("message", "인증번호가 일치하지 않습니다.");
            }

        } else {
            response.put("success", false);
            response.put("message", "잘못된 요청입니다.");
        }

        return ResponseEntity.ok(response);
    }
}
