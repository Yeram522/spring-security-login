package hashsnap.security.entity;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;

import java.time.Instant;

@Document(indexName = "security-logs")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityLogEvent {

    @Id
    private String id;

    @Field(type = FieldType.Date)
    private Instant timestamp;

    @Field(type = FieldType.Keyword)
    private String eventType;  // LOGIN_SUCCESS, LOGIN_FAILED, API_ACCESS 등

    @Field(type = FieldType.Keyword)
    private String httpMethod;

    @Field(type = FieldType.Keyword)
    private String email;

    @Field(type = FieldType.Ip)
    private String ipAddress;

    @Field(type = FieldType.Keyword)
    private String endpoint;

    @Field(type = FieldType.Integer)
    private Integer statusCode;

    @Field(type = FieldType.Long)
    private Long processingTimeMs;

    @Field(type = FieldType.Text)
    private String userAgent;

    @Field(type = FieldType.Keyword)
    private String failureReason;
}
