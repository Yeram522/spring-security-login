package hashsnap.security.filter;

import hashsnap.security.entity.SecurityLogEvent;
import hashsnap.security.service.SecurityLogService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityAuditFilter extends OncePerRequestFilter {

    private final SecurityLogService securityLogService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        log.info("SecurityAuditFilter 시작 - URI: {}", request.getRequestURI());
        try {
            filterChain.doFilter(request, response);
        } finally {
            log.info("SecurityAuditFilter 완료 - Status: {}", response.getStatus());
            logRequest(request, response, System.currentTimeMillis());
        }
    }

    private void logRequest(HttpServletRequest request, HttpServletResponse response, long startTime) {
        try {
            long processingTime = System.currentTimeMillis() - startTime;

            securityLogService.saveLogAsync(SecurityLogEvent.builder()
                    .eventType(determineEventType(request, response))
                    .endpoint(request.getRequestURI())
                    .httpMethod(request.getMethod())
                    .statusCode(response.getStatus())
                    .ipAddress(getClientIp(request))
                    .userAgent(request.getHeader("User-Agent"))
                    .email(getCurrentUserEmail()) // 이제 JWT 인증 완료된 상태에서 호출
                    .failureReason(getFailureReason(response))
                    .processingTimeMs(processingTime) // 추가 정보
                    .build());

        } catch (Exception e) {
            log.error("보안 감사 로그 저장 실패", e);
        }
    }
    private String determineEventType(HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();
        int status = response.getStatus();

        if (uri.startsWith("/admin/")) {
            if (status == 302) {
                return "ADMIN_ACCESS_UNAUTHORIZED"; // 인증되지 않은 접근
            } else if (status == 403) {
                return "ADMIN_ACCESS_DENIED"; // 권한 없는 접근
            } else {
                return "ADMIN_ACCESS_SUCCESS";
            }
        } else if (uri.contains("/auth/")) {
            return status >= 400 ? "AUTH_REQUEST_FAILED" : "AUTH_REQUEST_SUCCESS";
        } else if (uri.startsWith("/api/")) {
            return status >= 400 ? "API_REQUEST_FAILED" : "API_REQUEST_SUCCESS";
        }

        return "HTTP_REQUEST";
    }

    private String getFailureReason(HttpServletResponse response) {
        int status = response.getStatus();
        switch (status) {
            case 302: return "REDIRECT_TO_LOGIN";
            case 401: return "UNAUTHORIZED";
            case 403: return "ACCESS_DENIED";
            case 404: return "NOT_FOUND";
            case 500: return "INTERNAL_ERROR";
            default: return null;
        }
    }

    private String getCurrentUserEmail() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser")) {
                return auth.getName(); // email
            }
            return "anonymous";
        } catch (Exception e) {
            return "unknown";
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String uri = request.getRequestURI();
        // 정적 리소스는 로깅 제외
        return uri.startsWith("/css/") || uri.startsWith("/js/") ||
                uri.startsWith("/images/") || uri.equals("/favicon.ico");
    }
}
