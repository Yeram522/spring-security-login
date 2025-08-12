package hashsnap.security.aspect;

import hashsnap.login.dto.LoginRequestDto;
import hashsnap.login.dto.LoginResponseDto;
import hashsnap.security.entity.SecurityLogEvent;
import hashsnap.security.service.SecurityLogService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class LoginAuditAspect {

    private final SecurityLogService securityLogService;

    @AfterReturning(pointcut = "@annotation(hashsnap.login.annotation.LoginAudit)", returning = "result")
    public void logSuccessfulLogin(JoinPoint joinPoint, Object result) {
        // 성공 로그
        securityLogService.saveLogAsync(SecurityLogEvent.builder()
                .eventType("LOGIN_SUCCESS")
                .email(extractUserEmailFromResult(result))
                .ipAddress(getCurrentRequestIp())
                .endpoint("/api/auth/login")
                .statusCode(200)
                .build());
    }

    @AfterThrowing(pointcut = "@annotation(hashsnap.login.annotation.LoginAudit)", throwing = "ex")
    public void logFailedLogin(JoinPoint joinPoint, Exception ex) {
        // 실패 로그
        securityLogService.saveLogAsync(SecurityLogEvent.builder()
                .eventType("LOGIN_FAILED")
                .email(extractUserEmailFromArgs(joinPoint.getArgs()))
                .ipAddress(getCurrentRequestIp())
                .endpoint("/api/auth/login")
                .statusCode(401)
                .failureReason(ex.getClass().getSimpleName())
                .build());
    }

    // IP 주소 추출 메서드
    private String getCurrentRequestIp() {
        try {
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            if (requestAttributes instanceof ServletRequestAttributes) {
                HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();
                return getClientIp(request);
            }
            return "unknown";
        } catch (Exception e) {
            log.warn("IP 주소 추출 실패", e);
            return "unknown";
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }

    private String extractUserEmailFromArgs(Object[] args) {
        try {
            for (Object arg : args) {
                if (arg instanceof LoginRequestDto) {
                    return ((LoginRequestDto) arg).getEmail();
                }
                if (arg instanceof String) {
                    return (String) arg;
                }
            }
        } catch (Exception e) {
            log.warn("사용자 email 추출 실패", e);
        }
        return "unknown";
    }

    private String extractUserEmailFromResult(Object result) {
        try {
            if (result instanceof LoginResponseDto) {
                // LoginResponse에 email 필드가 있다면
                return ((LoginResponseDto) result).getUserEmail();
            }
            if (result instanceof String) {
                // JWT 토큰에서 추출 또는 기본값
                return "success_user";
            }
        } catch (Exception e) {
            log.warn("결과에서 사용자 email 추출 실패", e);
        }
        return "success_user";
    }
}
