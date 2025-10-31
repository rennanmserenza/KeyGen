using KeyGenerator.Enums;
using KeyGenerator.Objects;
using System.Security.Cryptography;
using System.Text;

namespace KeyGenerator.Generator;

public static class KeyGen
{
    /// <summary>
    /// Converte um array de bytes em uma string codificada em Base32.
    /// </summary>
    /// <param name="bytes">O array de bytes a ser convertido.</param>
    /// <returns>Uma string Base32 representando os dados binários fornecidos.</returns>
    /// <remarks>
    /// A codificação Base32 utiliza o alfabeto <c>A-Z</c> e <c>2-7</c>,
    /// conforme definido pela RFC 4648.  
    /// Esta função é útil para gerar identificadores seguros e legíveis,
    /// especialmente quando o uso de caracteres especiais (como em Base64)
    /// não é permitido — por exemplo, em URLs, nomes de arquivos ou tokens curtos.
    /// 
    /// O tamanho da saída é sempre um múltiplo de 8 caracteres por cada bloco
    /// de 5 bytes de entrada. Nenhum caractere de padding ('=') é adicionado.
    /// <example>
    /// Exemplo de uso:
    /// <code>
    /// byte[] data = { 0xFA, 0xBC, 0x12, 0x9D };
    /// string encoded = ToBase32String(data);
    /// Console.WriteLine(encoded); // Saída: "7VLKSAI"
    /// </code>
    /// </example>
    /// </remarks>
    private static string ToBase32String(byte[] bytes)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder result = new((bytes.Length + 4) / 5 * 8);

        int buffer = bytes[0];
        int next = 1;
        int bitsLeft = 8;
        while (bitsLeft > 0 || next < bytes.Length)
        {
            if (bitsLeft < 5)
            {
                if (next < bytes.Length)
                {
                    buffer <<= 8;
                    buffer |= bytes[next++] & 0xFF;
                    bitsLeft += 8;
                }
                else
                {
                    int pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }

            int index = buffer >> bitsLeft - 5 & 0x1F;
            bitsLeft -= 5;
            result.Append(alphabet[index]);
        }

        return result.ToString();
    }

    /// <summary>
    /// Gera uma chave criptograficamente segura no formato desejado.
    /// </summary>
    /// <param name="byteLength">Tamanho em bytes (não em bits!)</param>
    /// <param name="format">Formato de saída (Hex, Base64, Base64Url, Base32)</param>
    public static string GenerateKey(int byteLength, EOutputFormat format = EOutputFormat.Hex)
    {
        if (byteLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(byteLength), "O tamanho deve ser maior que zero.");

        byte[] key = new byte[byteLength];
        RandomNumberGenerator.Fill(key);

        return format switch
        {
            EOutputFormat.Hex => BitConverter.ToString(key).Replace("-", ""),
            EOutputFormat.Base64 => Convert.ToBase64String(key),
            EOutputFormat.Base64Url => Convert.ToBase64String(key)
                                            .TrimEnd('=')
                                            .Replace('+', '-')
                                            .Replace('/', '_'),
            EOutputFormat.Base32 => ToBase32String(key),
            _ => throw new NotSupportedException("Formato não suportado.")
        };
    }

    /// <summary>
    /// Gera uma chave ou token com base nas opções informadas.
    /// </summary>
    public static string GenerateKey(TokenGenerationOptions options)
    {
        byte[] keyBytes = new byte[options.ByteLength];
        RandomNumberGenerator.Fill(keyBytes);

        string encoded = options.Format switch
        {
            EOutputFormat.Hex => BitConverter.ToString(keyBytes).Replace("-", ""),
            EOutputFormat.Base64 => Convert.ToBase64String(keyBytes),
            EOutputFormat.Base64Url => Convert.ToBase64String(keyBytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('='),
            EOutputFormat.Base32 => ToBase32String(keyBytes),
            _ => throw new NotSupportedException($"Formato {options.Format} não suportado.")
        };

        string token = $"{options.Prefix}_{encoded}";

        if (options.Expiration.HasValue)
        {
            long ticks = DateTime.UtcNow.Add(options.Expiration.Value).Ticks;
            string exp = Convert.ToBase64String(BitConverter.GetBytes(ticks))
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
            token += $"_{exp}";
        }

        return token;
    }

    /// <summary>
    /// Gera um token estruturado com base nas opções fornecidas.
    /// </summary>
    public static string GenerateStructuredToken(TokenGenerationOptions options)
    {
        return GenerateKey(options);
    }

    /// <summary>
    /// Gera um token estruturado com parâmetros diretos.
    /// </summary>
    public static string GenerateStructuredToken(
        string prefix,
        int byteLength = 32,
        EOutputFormat format = EOutputFormat.Base64Url,
        TimeSpan? expiration = null)
    {
        var options = new TokenGenerationOptions(prefix, byteLength, format, expiration);
        return GenerateKey(options);
    }

    /// <summary>
    /// Valida e extrai informações de um token estruturado (prefixo, data e expiração).
    /// </summary>
    public static TokenInfo ParseStructuredToken(string compositeToken)
    {
        if (string.IsNullOrWhiteSpace(compositeToken))
            throw new ArgumentNullException(nameof(compositeToken));

        // Usa '_' pois o GenerateKey usa underscore como separador
        var parts = compositeToken.Split('_', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            throw new FormatException("Token estruturado inválido.");

        string prefix = parts[0];
        string tokenValue = parts[1];
        DateTime createdAt = DateTime.UtcNow; // não há timestamp embutido no formato atual
        DateTime? expiresAt = null;

        // Se houver uma parte de expiração (terceira parte)
        if (parts.Length > 2)
        {
            string expPart = parts[2];

            // Converte Base64Url para Base64 padrão
            string base64 = expPart.Replace('-', '+').Replace('_', '/');

            // Adiciona padding correto
            int mod4 = base64.Length % 4;
            if (mod4 > 0)
                base64 = base64.PadRight(base64.Length + (4 - mod4), '=');

            try
            {
                byte[] bytes = Convert.FromBase64String(base64);
                if (bytes.Length != 8) // long = 8 bytes
                    throw new FormatException("Expiração inválida (tamanho incorreto).");

                long ticks = BitConverter.ToInt64(bytes, 0);
                expiresAt = new DateTime(ticks, DateTimeKind.Utc);
            }
            catch (Exception ex)
            {
                throw new FormatException("A parte de expiração do token é inválida.", ex);
            }
        }

        return new TokenInfo(prefix, createdAt, expiresAt, tokenValue);
    }
}
