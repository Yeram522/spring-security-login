package hashsnap.login.controller;

import hashsnap.global.response.ApiResponse;
import hashsnap.login.dto.EmailCheckResponse;
import hashsnap.login.dto.EmailVerificationDto;
import hashsnap.login.dto.SignupRequestDto;
import hashsnap.login.exception.EmailVerificationException;
import hashsnap.login.exception.UserException.DuplicateUserException;
import hashsnap.login.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;


@RestController  // JSON 반환
@RequestMapping("/api")
@ResponseBody
@RequiredArgsConstructor
public class UserApiController {

    private final UserService userService;

    // 이메일 중복 확인 API
    @GetMapping("/users")
    public EmailCheckResponse checkEmailDuplicate(@RequestParam String email) {
        boolean exists = false;// userService.isEmailExists(email);
        return EmailCheckResponse.builder()
                .exists(exists)
                .build();
    }

    @PostMapping("/users")
    public ApiResponse signup(@Valid @RequestBody SignupRequestDto signupRequest) {
        try {
            //userService.signup(signupRequest);
            return ApiResponse.builder()
                    .success(true)
                    .message("회원가입이 완료되었습니다")
                    .build();
        } catch (DuplicateUserException e) {
            return ApiResponse.builder()
                    .success(false)
                    .message(e.getMessage())
                    .build();
        } catch (Exception e) {
            return ApiResponse.builder()
                    .success(false)
                    .message("회원가입 중 오류가 발생했습니다")
                    .build();
        }
    }

    @PostMapping("/email-verification")
    public ApiResponse handleEmailVerification(@Valid @RequestBody EmailVerificationDto request) {
        try {
            return switch (request.getAction()) {
                case "send" -> handleSendAction(request);
                case "verify" -> handleVerifyAction(request);
                default -> createErrorResponse("잘못된 요청입니다");
            };
        } catch (EmailVerificationException e) {
            return createErrorResponse(e.getMessage());
        } catch (Exception e) {
            return createErrorResponse("처리 중 오류가 발생했습니다");
        }
    }


    private ApiResponse handleSendAction(EmailVerificationDto request) {
        //emailVerificationService.sendVerificationCode(request.getEmail());
        return createSuccessResponse("인증번호가 발송되었습니다");
    }

    private ApiResponse handleVerifyAction(EmailVerificationDto request) {
        boolean isValid = true;/*emailVerificationService.verifyCode(
                request.getEmail(),
                request.getVerificationCode()
        );*/
        return isValid
                ? createSuccessResponse("인증이 완료되었습니다")
                : createErrorResponse("인증번호가 일치하지 않습니다");
    }

    // 응답 생성 헬퍼 메소드들
    private ApiResponse createSuccessResponse(String message) {
        return ApiResponse.builder()
                .success(true)
                .message(message)
                .build();
    }

    private ApiResponse createErrorResponse(String message) {
        return ApiResponse.builder()
                .success(false)
                .message(message)
                .build();
    }
}
