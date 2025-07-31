-- 데이터베이스 사용
USE userdb;

-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL COMMENT '이름',
    nickname VARCHAR(50) NOT NULL COMMENT '닉네임/표시명',
    password VARCHAR(100) NOT NULL COMMENT 'BCrypt 암호화된 비밀번호',
    phone VARCHAR(20) NOT NULL COMMENT '휴대폰 번호',
    email VARCHAR(100) NOT NULL UNIQUE COMMENT '이메일 주소',

    -- 계정 상태 관리
    status ENUM('ACTIVE', 'SUSPENDED', 'DELETED') DEFAULT 'ACTIVE' COMMENT '계정 상태',
    enabled BOOLEAN DEFAULT TRUE COMMENT '계정 활성화 여부',

    -- 보안 관련
    login_failure_count INT DEFAULT 0 COMMENT '로그인 실패 횟수 (5회 초과시 잠금)',
    email_verified BOOLEAN DEFAULT FALSE COMMENT '이메일 인증 여부',
    -- phone_verified BOOLEAN DEFAULT FALSE COMMENT '휴대폰 인증 여부',

    -- JWT 토큰 관리
    refresh_token VARCHAR(500) NULL COMMENT 'JWT 리프레시 토큰',
    refresh_token_expires_at DATETIME NULL COMMENT '리프레시 토큰 만료 시간',

    -- 시간 관리
    last_login_at DATETIME NULL COMMENT '마지막 로그인 시간',
    password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '비밀번호 변경 시간',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '계정 생성 시간',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '정보 수정 시간',

    -- 인덱스 추가 (자주 조회되는 컬럼들)
    INDEX idx_email (email) COMMENT '이메일로 사용자 찾기',
    INDEX idx_status (status) COMMENT '활성 사용자 조회',
    INDEX idx_refresh_token (refresh_token) COMMENT '토큰 검증 시 사용'
    ) COMMENT '사용자 정보 테이블';

-- 기본 계정 생성 (비밀번호: admin123)
INSERT IGNORE INTO users (
    username, nickname, password, phone, email,
    status, enabled, email_verified
) VALUES
(
    'testuser', '테스트유저',
    '$2a$10$e3bddd9fKxaBOWFFnTB3SO.go/2Xix7J.oSN.u124N8wim6j5uLOi',
    '010-9876-5432', 'user@example.com',
    'ACTIVE', TRUE, TRUE
);