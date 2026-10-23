package com.company.sso.common;

import java.time.Instant;
import java.util.Map;

public record ApiResponse<T>(boolean success, T data, String message, String errorCode,
                             Map<String, String> fieldErrors, Instant timestamp) {
    public static <T> ApiResponse<T> ok(T data) {
        return new ApiResponse<>(true, data, null, null, null, Instant.now());
    }
    public static ApiResponse<Void> error(String code, String message, Map<String, String> fieldErrors) {
        return new ApiResponse<>(false, null, message, code, fieldErrors, Instant.now());
    }
}
