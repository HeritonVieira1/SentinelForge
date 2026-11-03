using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SentinelForge.Application.Abstractions;
using SentinelForge.Infrastructure.Security;

namespace SentinelForge.Api.Security;

internal static class JwtConfiguration
{
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, JwtSettings settings)
    {
        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.MapInboundClaims = false;
                options.RequireHttpsMetadata = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = settings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = settings.Audience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = settings.CreateSigningKey(),
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                    ClockSkew = TimeSpan.FromSeconds(30),
                    NameClaimType = AuthClaims.Subject,
                    RoleClaimType = AuthClaims.Role,
                };
                options.Events = new JwtBearerEvents { OnTokenValidated = ValidateAgainstServerStateAsync };
            });

        return services;
    }

    /// <summary>
    /// O token não é a fonte da verdade: a cada requisição confirmamos no banco que o usuário continua ativo,
    /// que o papel não mudou e que a sessão não foi revogada. Assim, desativação, troca de papel e logout
    /// valem imediatamente, sem esperar o token expirar.
    /// </summary>
    private static async Task ValidateAgainstServerStateAsync(TokenValidatedContext context)
    {
        var principal = context.Principal;
        var ct = context.HttpContext.RequestAborted;

        if (!Guid.TryParse(principal?.FindFirst(AuthClaims.Subject)?.Value, out var userId)
            || !Guid.TryParse(principal.FindFirst(AuthClaims.Session)?.Value, out var sessionId))
        {
            context.Fail("Malformed token claims.");
            return;
        }

        var services = context.HttpContext.RequestServices;
        var user = await services.GetRequiredService<IUserRepository>().FindByIdAsync(userId, ct);

        if (user is null
            || !user.IsActive
            || !string.Equals(user.Role.ToString(), principal.FindFirst(AuthClaims.Role)?.Value, StringComparison.Ordinal)
            || !await services.GetRequiredService<IRefreshTokenRepository>().IsSessionActiveAsync(sessionId, userId, ct))
        {
            context.Fail("Token no longer valid.");
        }
    }
}
