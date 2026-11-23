package com.zerotrust.security.abac;

/**
 * ABAC Action: Defined operations on protected resources.
 */
public enum SecurityAction {
    READ,
    CREATE,
    UPDATE,
    DELETE,
    EXECUTE_TRANSACTION,
    VIEW_SENSITIVE
}
