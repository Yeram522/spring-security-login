package hashsnap.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.elasticsearch.repository.config.EnableElasticsearchRepositories;

@Configuration
@EnableElasticsearchRepositories(basePackages = "hashsnap.security.repository")
public class ElasticsearchConfig {
}
