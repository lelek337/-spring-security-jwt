package com.example.securityjwt;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record Token(UUID id, String subject, List<String> authorities, Instant createAt, Instant expiresAt) {
}