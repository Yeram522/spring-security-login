package hashsnap.global.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public abstract class ApiController {
    // 공통 API 기능이 필요하면 여기에 추가
    // 예: 공통 헤더 처리, 로깅, 인증 체크 등
}
