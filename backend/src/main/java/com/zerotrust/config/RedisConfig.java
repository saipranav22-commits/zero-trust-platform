package com.zerotrust.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisConnectionUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;

/**
 * Distributed Redis Configuration with Bounded Lettuce Timeouts.
 */
@Configuration
public class RedisConfig {

    @Value("${spring.data.redis.host:localhost}")
    private String redisHost;

    @Value("${spring.data.redis.port:6379}")
    private int redisPort;

    @Value("${spring.data.redis.password:}")
    private String redisPassword;

    @Value("${spring.data.redis.timeout:1000ms}")
    private Duration commandTimeout;

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        RedisStandaloneConfiguration serverConfig = new RedisStandaloneConfiguration(redisHost, redisPort);
        if (redisPassword != null && !redisPassword.isBlank()) {
            serverConfig.setPassword(redisPassword);
        }

        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
            .commandTimeout(commandTimeout)
            .shutdownTimeout(Duration.ofMillis(200))
            .build();

        return new LettuceConnectionFactory(serverConfig, clientConfig);
    }

    @Bean
    public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory connectionFactory) {
        return new StringRedisTemplate(connectionFactory);
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }

    /**
     * Resilient PING-based Redis Health Indicator.
     * Replaces the default Spring Boot INFO-based RedisHealthIndicator to ensure cross-platform
     * compatibility (specifically avoiding java.util.Properties Unicode escape parser
     * failures when Redis for Windows outputs backslash file paths in INFO output),
     * while guaranteeing strict, accurate UP / DOWN health reporting.
     *
     * - Returns UP with detail {"ping": "PONG", "status": "UP"} when Redis is reachable and responds to PING.
     * - Returns DOWN when Redis is unreachable, connection fails, or unexpected response is received.
     * - Overrides default contributor without duplicate or conflicting health indicators.
     */
    @Bean("redisHealthIndicator")
    public HealthIndicator redisHealthIndicator(RedisConnectionFactory connectionFactory) {
        return new AbstractHealthIndicator("Redis health check failed") {
            @Override
            protected void doHealthCheck(Health.Builder builder) throws Exception {
                RedisConnection connection = RedisConnectionUtils.getConnection(connectionFactory);
                try {
                    String pong = connection.ping();
                    if ("PONG".equalsIgnoreCase(pong)) {
                        builder.up()
                            .withDetail("ping", pong)
                            .withDetail("status", "UP");
                    } else {
                        builder.down()
                            .withDetail("ping", pong)
                            .withDetail("error", "Unexpected response from Redis PING");
                    }
                } finally {
                    RedisConnectionUtils.releaseConnection(connection, connectionFactory);
                }
            }
        };
    }
}
