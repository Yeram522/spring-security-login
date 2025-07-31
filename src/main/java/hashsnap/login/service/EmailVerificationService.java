package hashsnap.login.service;

import hashsnap.login.exception.EmailVerificationException;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

/**
 * 이메일 인증 서비스
 * JavaMailSender 기반 인증번호 발송 및 검증
 * HttpSession을 활용한 임시 인증 상태 관리 (5분 만료)
 */
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final JavaMailSender mailSender;

    private final HttpSession session;

    private static final String VERIFICATION_CODE_PREFIX = "verification_code_";
    private static final String VERIFICATION_TIME_PREFIX = "verification_time_";
    private static final int CODE_EXPIRY_MINUTES = 5; // 인증번호 유효시간 5분

    // 인증번호 생성 (6자리 숫자)
    private String generateVerificationCode() {
        SecureRandom random = new SecureRandom();
        int code = 100000 + random.nextInt(900000);
        return String.valueOf(code);
    }

    // 인증번호 발송
    public void sendVerificationCode(String email, String purpose) {
        String verificationCode = generateVerificationCode();

        // 세션에 인증번호와 생성시간 저장
        String sessionKey = VERIFICATION_CODE_PREFIX + purpose + "_" + email;
        String timeKey = VERIFICATION_TIME_PREFIX + purpose + "_" + email;

        session.setAttribute(sessionKey, verificationCode);
        session.setAttribute(timeKey, LocalDateTime.now());

        // 이메일 발송
        sendEmail(email, verificationCode, purpose);
    }

    // 이메일 발송 실제 로직
    private void sendEmail(String toEmail, String verificationCode, String purpose) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(toEmail);
            message.setSubject(getEmailSubject(purpose));
            message.setText(getEmailContent(verificationCode, purpose));
            message.setFrom("yelamg963@gmail.com"); // 발신자 이메일

            mailSender.send(message);
        } catch (Exception e) {
            throw new EmailVerificationException("이메일 발송에 실패했습니다: " + e.getMessage());
        }
    }

    // 이메일 제목 생성
    private String getEmailSubject(String purpose) {
        return switch (purpose) {
            case "signup" -> "[회원가입] 이메일 인증번호";
            case "password-reset" -> "[비밀번호 재설정] 이메일 인증번호";
            default -> "[인증] 이메일 인증번호";
        };
    }

    // 이메일 내용 생성
    private String getEmailContent(String verificationCode, String purpose) {
        String actionText = switch (purpose) {
            case "signup" -> "회원가입";
            case "password-reset" -> "비밀번호 재설정";
            default -> "인증";
        };

        return String.format("""
            안녕하세요!
            
            %s을 위한 이메일 인증번호입니다.
            
            인증번호: %s
            
            이 인증번호는 %d분간 유효합니다.
            인증번호를 정확히 입력해주세요.
            
            본인이 요청하지 않은 경우, 이 이메일을 무시해주세요.
            
            감사합니다.
            """, actionText, verificationCode, CODE_EXPIRY_MINUTES);
    }

    // 인증번호 검증
    public boolean verifyCode(String email, String inputCode, String purpose) {
        String sessionKey = VERIFICATION_CODE_PREFIX + purpose + "_" + email;
        String timeKey = VERIFICATION_TIME_PREFIX + purpose + "_" + email;

        String storedCode = (String) session.getAttribute(sessionKey);
        LocalDateTime createdTime = (LocalDateTime) session.getAttribute(timeKey);

        // 세션에 인증번호가 없는 경우
        if (storedCode == null || createdTime == null) {
            throw new EmailVerificationException("인증번호를 먼저 발송해주세요");
        }

        // 인증번호 만료 체크 (5분)
        if (ChronoUnit.MINUTES.between(createdTime, LocalDateTime.now()) > CODE_EXPIRY_MINUTES) {
            // 만료된 인증번호 세션에서 제거
            session.removeAttribute(sessionKey);
            session.removeAttribute(timeKey);
            throw new EmailVerificationException("인증번호가 만료되었습니다. 새로운 인증번호를 요청해주세요");
        }

        // 인증번호 일치 확인
        boolean isValid = storedCode.equals(inputCode);

        if (isValid) {
            // 인증 성공 시 세션에서 제거
            session.removeAttribute(sessionKey);
            session.removeAttribute(timeKey);

            // 인증 완료 표시 (필요한 경우)
            session.setAttribute("email_verified_" + purpose + "_" + email, true);
        }

        return isValid;
    }

    // 이메일 인증 완료 여부 확인
    public boolean isEmailVerified(String email, String purpose) {
        Boolean verified = (Boolean) session.getAttribute("email_verified_" + purpose + "_" + email);
        return verified != null && verified;
    }

    // 인증 상태 초기화 (회원가입 완료 후 호출)
    public void clearVerificationStatus(String email, String purpose) {
        session.removeAttribute("email_verified_" + purpose + "_" + email);
    }
}
