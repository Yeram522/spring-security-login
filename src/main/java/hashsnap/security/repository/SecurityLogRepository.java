package hashsnap.security.repository;

import hashsnap.security.model.SecurityLogEvent;
import org.springframework.data.elasticsearch.annotations.Query;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityLogRepository extends ElasticsearchRepository<SecurityLogEvent, String> {
    // 이벤트 타입으로 조회
    List<SecurityLogEvent> findByEventType(String eventType);

    // 특정 시간 이후 이벤트 조회
    List<SecurityLogEvent> findByTimestampAfter(LocalDateTime timestamp);

    // IP 주소로 조회
    List<SecurityLogEvent> findByIpAddress(String ipAddress);

    // 이메일 인증 실패 로그 조회
    @Query("""
        {
          "bool": {
            "must": [
              {"wildcard": {"endpoint": "*auth/email/verify*"}},
              {"range": {"timestamp": {"gte": "?0"}}},
              {"range": {"statusCode": {"gte": 400}}}
            ]
          }
        }
        """)
    List<SecurityLogEvent> findEmailVerificationFailures(String fromTime);

    // IP별 이메일 인증 실패 카운트
    @Query("""
        {
          "bool": {
            "must": [
              {"wildcard": {"endpoint": "*auth/email/verify*"}},
              {"range": {"timestamp": {"gte": "?0"}}},
              {"range": {"statusCode": {"gte": 400}}},
              {"term": {"ipAddress.keyword": "?1"}}
            ]
          }
        }
        """)
    List<SecurityLogEvent> findEmailVerificationFailuresByIp(String fromTime, String ipAddress);

    // API 남용 탐지
    @Query("""
    {
      "bool": {
        "must": [
          {"wildcard": {"endpoint": "/api/*"}},
          {"range": {"timestamp": {"gte": "?0"}}}
        ]
      }
    }
    """)
    List<SecurityLogEvent> findApiCallsAfter(String fromTime);

    // Admin 스캐닝 탐지
    @Query("""
    {
      "bool": {
        "must": [
          {"wildcard": {"endpoint": "*admin*"}},
          {"range": {"timestamp": {"gte": "?0"}}},
          {"terms": {"statusCode": [401, 403, 302]}}
        ]
      }
    }
    """)
    List<SecurityLogEvent> findAdminAccessAttempts(String fromTime);

    // 404 에러만 조회
    @Query("""
    {
      "bool": {
        "must": [
          {"range": {"timestamp": {"gte": "?0"}}},
          {"term": {"statusCode": 404}}
        ]
      }
    }
    """)
    List<SecurityLogEvent> findNotFoundErrorsAfter(String fromTime);

    // 응답시간이 있는 로그만 조회
    @Query("""
    {
      "bool": {
        "must": [
          {"range": {"timestamp": {"gte": "?0"}}},
          {"exists": {"field": "processingTimeMs"}}
        ]
      }
    }
    """)
    List<SecurityLogEvent> findLogsWithResponseTimeAfter(String fromTime);

    // 특정 시간 범위의 로그 조회
    @Query("""
    {
      "bool": {
        "must": [
          {"range": {"timestamp": {"gte": "?0", "lt": "?1"}}},
          {"exists": {"field": "processingTimeMs"}}
        ]
      }
    }
    """)
    List<SecurityLogEvent> findLogsBetweenTimes(String fromTime, String toTime);
}
