namespace SentinelForge.Application;

/// <summary>Parâmetros de autenticação (seção "Auth" da configuração).</summary>
public sealed class AuthOptions
{
    public int MaxFailedLoginAttempts { get; set; } = 5;

    public int LockoutMinutes { get; set; } = 15;

    public int RefreshTokenDays { get; set; } = 7;
}
