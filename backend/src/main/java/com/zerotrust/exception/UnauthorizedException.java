package com.zerotrust.exception;

import org.springframework.http.HttpStatus;

public class UnauthorizedException extends RuntimeException {
    public UnauthorizedException(String message) { super(message); }
    public HttpStatus getStatus() { return HttpStatus.UNAUTHORIZED; }
}
