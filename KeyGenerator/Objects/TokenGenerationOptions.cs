using KeyGenerator.Enums;

namespace KeyGenerator.Objects;

// Novo record para encapsular as opções
public record TokenGenerationOptions(
    string Prefix,
    int ByteLength = 32,
    EOutputFormat Format = EOutputFormat.Base64Url,
    TimeSpan? Expiration = null
);
