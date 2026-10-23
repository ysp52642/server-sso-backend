package com.company.sso.common;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CryptoSupportTest {
    @Test
    void generatesUrlSafeOpaqueTokensAndStableHashes() {
        String token = CryptoSupport.newOpaqueToken();
        assertThat(token).doesNotContain("=").hasSizeGreaterThan(50);
        assertThat(CryptoSupport.sha256("value")).isEqualTo(CryptoSupport.sha256("value")).hasSize(64);
        assertThat(CryptoSupport.sha256("value")).isNotEqualTo(CryptoSupport.sha256("different"));
    }

    @Test
    void comparesSecretsInConstantTimeAndNormalizesCodes() {
        assertThat(CryptoSupport.constantTimeEquals("secret", "secret")).isTrue();
        assertThat(CryptoSupport.constantTimeEquals("secret", "other")).isFalse();
        assertThat(CryptoSupport.normalizedCode(" employee_portal ")).isEqualTo("EMPLOYEE_PORTAL");
    }
}
