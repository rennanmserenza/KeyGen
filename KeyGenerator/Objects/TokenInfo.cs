namespace KeyGenerator.Objects;

public record TokenInfo(
    string Prefix,
    DateTime CreatedAt,
    DateTime? ExpiresAt,
    string Token
);
