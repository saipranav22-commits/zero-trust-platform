package com.zerotrust.exception;

/**
 * Thrown when an invalid incident state transition is attempted
 * (e.g. attempting OPEN -> RESOLVED directly without investigation).
 */
public class InvalidStateTransitionException extends ValidationException {
    public InvalidStateTransitionException(String message) {
        super(message);
    }
}
