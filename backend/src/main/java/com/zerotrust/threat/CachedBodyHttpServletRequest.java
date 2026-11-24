package com.zerotrust.threat;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * Request wrapper providing strictly bounded repeatable body reads for
 * text/JSON requests.
 * Caps cached content at maxPayloadBytes (default 64KB) to avoid memory or
 * ReDoS attacks.
 * Correctly detects overflow for both known Content-Length and chunked
 * Transfer-Encoding
 * by reading at most maxPayloadBytes + 1 bytes.
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] cachedBody;
    private final boolean isBodyCached;
    private final boolean isPayloadTooLarge;
    private final boolean isTextOrJson;

    public CachedBodyHttpServletRequest(HttpServletRequest request, int maxPayloadBytes) throws IOException {
        super(request);
        String contentType = request.getContentType();
        int contentLength = request.getContentLength();
        String clHeader = request.getHeader("Content-Length");
        if (clHeader != null) {
            try {
                int parsedCl = Integer.parseInt(clHeader.trim());
                if (parsedCl > contentLength) {
                    contentLength = parsedCl;
                }
            } catch (NumberFormatException ignored) {
            }
        }

        this.isTextOrJson = contentType != null && (contentType.toLowerCase().contains("application/json") ||
                contentType.toLowerCase().contains("application/x-www-form-urlencoded") ||
                contentType.toLowerCase().contains("text/"));

        if (this.isTextOrJson) {
            if (contentLength > maxPayloadBytes) {
                this.cachedBody = new byte[0];
                this.isBodyCached = false;
                this.isPayloadTooLarge = true;
            } else {
                // Known length <= maxPayloadBytes OR chunked/unknown length (contentLength == -1)
                // Cap initial capacity strictly independently of client-supplied Content-Length (fixed 1024 bytes)
                // Buffer grows dynamically up to at most maxPayloadBytes + 1 bytes
                ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
                InputStream is = request.getInputStream();
                byte[] buffer = new byte[4096];
                int totalRead = 0;
                int read;
                boolean overflow = false;

                while ((read = is.read(buffer)) != -1) {
                    int remainingAllowed = (maxPayloadBytes + 1) - totalRead;
                    if (remainingAllowed <= 0) {
                        overflow = true;
                        break;
                    }
                    int toWrite = Math.min(read, remainingAllowed);
                    baos.write(buffer, 0, toWrite);
                    totalRead += read;
                    if (totalRead > maxPayloadBytes) {
                        overflow = true;
                        break;
                    }
                }

                if (overflow || totalRead > maxPayloadBytes) {
                    this.cachedBody = new byte[0];
                    this.isBodyCached = false;
                    this.isPayloadTooLarge = true;
                } else {
                    this.cachedBody = baos.toByteArray();
                    this.isBodyCached = true;
                    this.isPayloadTooLarge = false;
                }
            }
        } else {
            // Non-text/JSON (e.g. multipart/form-data, binary octet-stream)
            this.cachedBody = new byte[0];
            this.isBodyCached = false;
            this.isPayloadTooLarge = false;
        }
    }

    public boolean isBodyCached() {
        return isBodyCached;
    }

    public boolean isPayloadTooLarge() {
        return isPayloadTooLarge;
    }

    public boolean isTextOrJson() {
        return isTextOrJson;
    }

    public String getBodyAsString() {
        if (!isBodyCached || cachedBody.length == 0) {
            return "";
        }
        return new String(cachedBody, StandardCharsets.UTF_8);
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (!isBodyCached) {
            return super.getInputStream();
        }

        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(cachedBody);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return byteArrayInputStream.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
            }

            @Override
            public int read() {
                return byteArrayInputStream.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() throws IOException {
        if (!isBodyCached) {
            return super.getReader();
        }
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }
}
