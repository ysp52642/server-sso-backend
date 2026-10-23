package com.company.sso.common;

import org.springframework.http.HttpStatus;

import java.util.Map;

public class ApiException extends RuntimeException {
    private final HttpStatus status;
    private final String errorCode;
    private final Map<String, String> fieldErrors;

    public ApiException(HttpStatus status, String errorCode, String message) {
        this(status, errorCode, message, null);
    }
    public ApiException(HttpStatus status, String errorCode, String message, Map<String, String> fieldErrors) {
        super(message);
        this.status = status;
        this.errorCode = errorCode;
        this.fieldErrors = fieldErrors;
    }
    public HttpStatus status() { return status; }
    public String errorCode() { return errorCode; }
    public Map<String, String> fieldErrors() { return fieldErrors; }
}
