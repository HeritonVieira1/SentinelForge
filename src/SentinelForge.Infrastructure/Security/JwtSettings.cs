using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace SentinelForge.Infrastructure.Security;

/// <summary>
/// Configuração do JWT (seção "Jwt"). A chave de assinatura vem exclusivamente de configuração externa
/// (variável de ambiente Jwt__SigningKey ou user-secrets) e a aplicação não inicia sem uma chave forte.
/// </summary>
public sealed class JwtSettings
{
    public const string SectionName = "Jwt";
    public const int MinSigningKeyLength = 32;

    public string Issuer { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;

    public string SigningKey { get; set; } = string.Empty;

    public int AccessTokenMinutes { get; set; } = 15;

    public static JwtSettings FromConfiguration(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var settings = configuration.GetSection(SectionName).Get<JwtSettings>() ?? new JwtSettings();
        settings.Validate();
        return settings;
    }

    public SymmetricSecurityKey CreateSigningKey() => new(Encoding.UTF8.GetBytes(SigningKey));

    private void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer) || string.IsNullOrWhiteSpace(Audience))
        {
            throw new InvalidOperationException("Jwt:Issuer and Jwt:Audience must be configured.");
        }

        if (SigningKey is null || SigningKey.Length < MinSigningKeyLength)
        {
            throw new InvalidOperationException(
                $"Jwt:SigningKey must be provided via configuration (environment variable Jwt__SigningKey) with at least {MinSigningKeyLength} characters.");
        }

        if (AccessTokenMinutes is < 1 or > 60)
        {
            throw new InvalidOperationException("Jwt:AccessTokenMinutes must be between 1 and 60.");
        }
    }
}
