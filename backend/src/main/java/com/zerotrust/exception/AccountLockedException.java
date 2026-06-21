package com.zerotrust.exception;

import org.springframework.http.HttpStatus;

public class AccountLockedException extends RuntimeException {
    public AccountLockedException(String message) { super(message); }
    public HttpStatus getStatus() { return HttpStatus.LOCKED; }
}
