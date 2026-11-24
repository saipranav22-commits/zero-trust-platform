package com.zerotrust.threat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class CachedBodyHttpServletRequestTest {

    private static final int MAX_BYTES = 65536; // 64 KB

    @Test
    @DisplayName("1. Legitimate JSON request within 64KB is cached and readable repeatably")
    void testNormalJsonWithinLimit() throws IOException {
        String json = "{\"name\":\"Alice\",\"role\":\"ADMIN\"}";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("application/json");
        request.setContent(json.getBytes(StandardCharsets.UTF_8));

        CachedBodyHttpServletRequest wrapper = new CachedBodyHttpServletRequest(request, MAX_BYTES);

        assertThat(wrapper.isTextOrJson()).isTrue();
        assertThat(wrapper.isBodyCached()).isTrue();
        assertThat(wrapper.isPayloadTooLarge()).isFalse();
        assertThat(wrapper.getBodyAsString()).isEqualTo(json);

        // Verify stream can be read repeatedly
        byte[] firstRead = wrapper.getInputStream().readAllBytes();
        byte[] secondRead = wrapper.getInputStream().readAllBytes();
        assertThat(firstRead).isEqualTo(json.getBytes(StandardCharsets.UTF_8));
        assertThat(secondRead).isEqualTo(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("2. Known Content-Length > 64KB is flagged as payload too large without buffering")
    void testKnownOversizedContentLength() throws IOException {
        byte[] oversizedData = new byte[70000];
        java.util.Arrays.fill(oversizedData, (byte) 'A');

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("application/json");
        request.setContent(oversizedData);
        request.addHeader("Content-Length", "70000");

        CachedBodyHttpServletRequest wrapper = new CachedBodyHttpServletRequest(request, MAX_BYTES);

        assertThat(wrapper.isTextOrJson()).isTrue();
        assertThat(wrapper.isPayloadTooLarge()).isTrue();
        assertThat(wrapper.isBodyCached()).isFalse();
    }

    @Test
    @DisplayName("3. Chunked Transfer-Encoding (Content-Length = -1) exceeding 64KB detects overflow and bounds heap")
    void testChunkedOversizedBody() throws IOException {
        byte[] largeData = new byte[70000];
        java.util.Arrays.fill(largeData, (byte) 'A');

        MockHttpServletRequest request = new MockHttpServletRequest() {
            @Override
            public int getContentLength() {
                return -1; // Chunked encoding
            }
        };
        request.setContentType("application/json;charset=UTF-8");
        request.setContent(largeData);

        CachedBodyHttpServletRequest wrapper = new CachedBodyHttpServletRequest(request, MAX_BYTES);

        assertThat(wrapper.isPayloadTooLarge()).isTrue();
        assertThat(wrapper.isBodyCached()).isFalse();
    }

    @Test
    @DisplayName("4. Boundary test: Exactly at 64KB limit is accepted")
    void testExactlyAtLimit() throws IOException {
        byte[] exactData = new byte[MAX_BYTES];
        java.util.Arrays.fill(exactData, (byte) 'B');

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("application/json");
        request.setContent(exactData);

        CachedBodyHttpServletRequest wrapper = new CachedBodyHttpServletRequest(request, MAX_BYTES);

        assertThat(wrapper.isPayloadTooLarge()).isFalse();
        assertThat(wrapper.isBodyCached()).isTrue();
        assertThat(wrapper.getInputStream().readAllBytes().length).isEqualTo(MAX_BYTES);
    }

    @Test
    @DisplayName("5. Boundary test: Exactly 64KB + 1 byte triggers overflow detection")
    void testOneByteOverLimit() throws IOException {
        byte[] overLimit = new byte[MAX_BYTES + 1];
        java.util.Arrays.fill(overLimit, (byte) 'C');

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("application/json");
        request.setContent(overLimit);

        CachedBodyHttpServletRequest wrapper = new CachedBodyHttpServletRequest(request, MAX_BYTES);

        assertThat(wrapper.isPayloadTooLarge()).isTrue();
        assertThat(wrapper.isBodyCached()).isFalse();
    }

    @Test
    @DisplayName("6. Non-text binary/multipart content bypasses caching without payload too large error")
    void testNonTextContentBypasses() throws IOException {
        byte[] binaryData = new byte[100000];
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("multipart/form-data; boundary=---12345");
        request.setContent(binaryData);

        CachedBodyHttpServletRequest wrapper = new CachedBodyHttpServletRequest(request, MAX_BYTES);

        assertThat(wrapper.isTextOrJson()).isFalse();
        assertThat(wrapper.isPayloadTooLarge()).isFalse();
        assertThat(wrapper.isBodyCached()).isFalse();
    }

    @Test
    @DisplayName("7. Extremely large declared Content-Length (e.g. 2 GB) rejects immediately without proportional heap allocation")
    void testExtremelyLargeDeclaredContentLengthNoAllocation() throws IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContentType("application/json");
        request.setContent("dummy".getBytes(StandardCharsets.UTF_8));
        request.addHeader("Content-Length", "2000000000"); // 2 GB declared length

        long beforeMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        CachedBodyHttpServletRequest wrapper = new CachedBodyHttpServletRequest(request, MAX_BYTES);
        long afterMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();

        assertThat(wrapper.isPayloadTooLarge()).isTrue();
        assertThat(wrapper.isBodyCached()).isFalse();
        // Memory difference must be negligible (less than 1 MB, definitely not 2 GB)
        assertThat(afterMemory - beforeMemory).isLessThan(1024 * 1024);
    }
}
