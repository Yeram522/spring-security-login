package hashsnap.security.repository;

import hashsnap.security.model.SecurityLogEvent;
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

}
