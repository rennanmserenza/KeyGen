using KeyGenerator.Enums;
using KeyGenerator.Generator;
using KeyGenerator.Objects;

// 🔐 Geração de chaves básicas
Console.WriteLine($"ValidationKey: {KeyGen.GenerateKey(64)}");                                  // 128 hex chars
Console.WriteLine($"DecryptionKey: {KeyGen.GenerateKey(24)}");                                  // 48 hex chars
Console.WriteLine($"AES Key: {KeyGen.GenerateKey(32)}");                                        // 256-bit AES key
Console.WriteLine($"AES IV: {KeyGen.GenerateKey(16)}");                                         // 128-bit IV

Console.WriteLine($"\nSalt: {KeyGen.GenerateKey(16)}");                                         // 128-bit salt
Console.WriteLine($"Token Key: {KeyGen.GenerateKey(32)}");                                      // 256-bit token

// 🪪 Geração de tokens estruturados
Console.WriteLine($"\nAPY Key: {KeyGen.GenerateKey(40, EOutputFormat.Base64Url)}");              // 320-bit API Key
Console.WriteLine($"File Id: {KeyGen.GenerateKey(12, EOutputFormat.Base32)}");                   // 96-bit - Identificador curto e unico
Console.WriteLine($"TMP password: {KeyGen.GenerateKey(8, EOutputFormat.Base64)}");               // 16-bit - password temporário
Console.WriteLine($"Nonce : {KeyGen.GenerateKey(16, EOutputFormat.Base64Url)}");                 // 128-bit - Nonce Generate

var apiToken = KeyGen.GenerateStructuredToken(new TokenGenerationOptions(
    Prefix: "API",
    ByteLength: 32,
    Format: EOutputFormat.Base64Url
));

var tempToken = KeyGen.GenerateStructuredToken(new TokenGenerationOptions(
    Prefix: "TEMP",
    ByteLength: 16,
    Format: EOutputFormat.Base32,
    Expiration: TimeSpan.FromMinutes(30)
));

var fileId = KeyGen.GenerateStructuredToken(new TokenGenerationOptions(
    Prefix: "File",
    ByteLength: 12,
    Format: EOutputFormat.Base32
));

// 🪪 Geração de tokens estruturados
Console.WriteLine($"\nAPI Key: {apiToken}");
Console.WriteLine($"TEMP Token (expira em 10 min): {tempToken}");
Console.WriteLine($"FILE ID: {fileId}");

// 🔍 Extraindo informações
var token = KeyGen.GenerateStructuredToken(new TokenGenerationOptions(
    Prefix: "LOGIN",
    ByteLength: 24,
    Format: EOutputFormat.Base64Url,
    Expiration: TimeSpan.FromHours(1)
));
var tokenInfo = KeyGen.ParseStructuredToken(token);

Console.WriteLine($"\nToken gerado: {token}");
Console.WriteLine($"Prefixo: {tokenInfo.Prefix}");
Console.WriteLine($"Criado em: {tokenInfo.CreatedAt:u}");
Console.WriteLine($"Expira em: {tokenInfo.ExpiresAt:u}");
Console.WriteLine($"Valor criptográfico: {tokenInfo.Token}");