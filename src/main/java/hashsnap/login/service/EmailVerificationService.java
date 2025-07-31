package hashsnap.login.service;

import hashsnap.login.exception.EmailVerificationException;
import hashsnap.login.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
@RequiredArgsConstructor
public class EmailVerificationService {

    private final UserRepository userRepository;

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
        // password-reset인 경우 사용자 존재 여부 확인
        if ("password-reset".equals(purpose) && !userRepository.existsByEmail(email)) {
            throw new EmailVerificationException("존재하지 않는 메일입니다");
        }

        try {
            String verificationCode = generateVerificationCode();

            // 세션에 인증번호와 생성시간 저장
            String sessionKey = VERIFICATION_CODE_PREFIX + purpose + "_" + email;
            String timeKey = VERIFICATION_TIME_PREFIX + purpose + "_" + email;

            session.setAttribute(sessionKey, verificationCode);
            session.setAttribute(timeKey, LocalDateTime.now());

            // 이메일 발송
            sendEmail(email, verificationCode, purpose);

        }catch (Exception e) {
            log.error("이메일 발송 실패: email={}, purpose={}", email, purpose, e);
            throw new EmailVerificationException("이메일 발송에 실패했습니다");
        }
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
    public void verifyCode(String email, String verificationCode, String purpose) {
        // 1. 기본 검증
        validateInput(verificationCode);

        // 2. 세션 데이터 조회 및 검증
        String[] sessionData = getAndValidateSession(email, purpose);
        String storedCode = sessionData[0];

        // 3. 인증번호 확인
        if (!storedCode.equals(verificationCode)) {
            throw new EmailVerificationException("인증번호가 일치하지 않습니다");
        }

        // 4. 성공 처리
        handleSuccessfulVerification(email, purpose);
    }

    private void validateInput(String verificationCode) {
        if (verificationCode == null || verificationCode.trim().isEmpty()) {
            throw new EmailVerificationException("인증번호를 입력해주세요");
        }
    }

    private String[] getAndValidateSession(String email, String purpose) {
        String sessionKey = VERIFICATION_CODE_PREFIX + purpose + "_" + email;
        String timeKey = VERIFICATION_TIME_PREFIX + purpose + "_" + email;

        String storedCode = (String) session.getAttribute(sessionKey);
        LocalDateTime createdTime = (LocalDateTime) session.getAttribute(timeKey);

        // 존재 여부 확인
        if (storedCode == null || createdTime == null) {
            throw new EmailVerificationException("인증번호를 먼저 발송해주세요");
        }

        // 만료 확인
        if (ChronoUnit.MINUTES.between(createdTime, LocalDateTime.now()) > CODE_EXPIRY_MINUTES) {
            clearSession(sessionKey, timeKey);
            throw new EmailVerificationException("인증번호가 만료되었습니다. 새로운 인증번호를 요청해주세요");
        }

        return new String[]{storedCode};
    }

    private void clearSession(String sessionKey, String timeKey) {
        session.removeAttribute(sessionKey);
        session.removeAttribute(timeKey);
    }

    private void handleSuccessfulVerification(String email, String purpose) {
        String sessionKey = VERIFICATION_CODE_PREFIX + purpose + "_" + email;
        String timeKey = VERIFICATION_TIME_PREFIX + purpose + "_" + email;

        // 인증 세션 정리
        clearSession(sessionKey, timeKey);

        // 인증 완료 표시
        session.setAttribute("email_verified_" + purpose + "_" + email, true);
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
