package com.zerotrust.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisHealthIndicatorTest {

    @Mock
    private RedisConnectionFactory redisConnectionFactory;

    @Mock
    private RedisConnection redisConnection;

    private final RedisConfig redisConfig = new RedisConfig();

    @Test
    @DisplayName("Health is UP when Redis connection responds with PONG")
    void shouldReportUpWhenRedisRespondsWithPong() {
        when(redisConnectionFactory.getConnection()).thenReturn(redisConnection);
        when(redisConnection.ping()).thenReturn("PONG");

        HealthIndicator indicator = redisConfig.redisHealthIndicator(redisConnectionFactory);
        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails())
                .containsEntry("ping", "PONG")
                .containsEntry("status", "UP");

        verify(redisConnection).close();
    }

    @Test
    @DisplayName("Health is DOWN when Redis connection throws connection failure exception")
    void shouldReportDownWhenRedisConnectionFails() {
        when(redisConnectionFactory.getConnection())
                .thenThrow(new RedisConnectionFailureException("Connection refused: connect"));

        HealthIndicator indicator = redisConfig.redisHealthIndicator(redisConnectionFactory);
        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsKey("error");
    }

    @Test
    @DisplayName("Health is DOWN when Redis ping returns unexpected payload")
    void shouldReportDownWhenRedisPingReturnsUnexpectedPayload() {
        when(redisConnectionFactory.getConnection()).thenReturn(redisConnection);
        when(redisConnection.ping()).thenReturn("UNEXPECTED");

        HealthIndicator indicator = redisConfig.redisHealthIndicator(redisConnectionFactory);
        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails())
                .containsEntry("ping", "UNEXPECTED")
                .containsEntry("error", "Unexpected response from Redis PING");

        verify(redisConnection).close();
    }
}
