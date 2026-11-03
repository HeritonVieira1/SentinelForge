using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using SentinelForge.Application.Abstractions;

namespace SentinelForge.Infrastructure.Security;

/// <summary>
/// Hash de senha com o PasswordHasher do ASP.NET Core Identity (formato v3: PBKDF2-HMAC-SHA512, salt aleatório
/// por senha). A contagem de iterações segue a recomendação atual da OWASP; hashes com contagem menor são
/// sinalizados para rehash no próximo login.
/// </summary>
internal sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    public const int IterationCount = 210_000;

    private static readonly object Subject = new();

    private readonly PasswordHasher<object> _inner = new(Options.Create(new PasswordHasherOptions { IterationCount = IterationCount }));
    private readonly Lazy<string> _dummyHash;

    public Pbkdf2PasswordHasher() =>
        _dummyHash = new Lazy<string>(() => _inner.HashPassword(Subject, Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16))));

    public string DummyHash => _dummyHash.Value;

    public string Hash(string password) => _inner.HashPassword(Subject, password);

    public PasswordVerification Verify(string hash, string password) =>
        _inner.VerifyHashedPassword(Subject, hash, password) switch
        {
            PasswordVerificationResult.Success => PasswordVerification.Success,
            PasswordVerificationResult.SuccessRehashNeeded => PasswordVerification.SuccessRehashNeeded,
            _ => PasswordVerification.Failed,
        };
}
