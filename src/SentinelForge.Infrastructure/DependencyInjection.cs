using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SentinelForge.Application.Abstractions;
using SentinelForge.Infrastructure.Auditing;
using SentinelForge.Infrastructure.Cve;
using SentinelForge.Infrastructure.Persistence;
using SentinelForge.Infrastructure.Persistence.Repositories;
using SentinelForge.Infrastructure.Security;

namespace SentinelForge.Infrastructure;

public static class DependencyInjection
{
    public const string ConnectionStringName = "DefaultConnection";

    /// <summary>
    /// Registra a infraestrutura. Segredos (connection string e chave JWT) vêm de configuração externa
    /// (variáveis de ambiente ConnectionStrings__DefaultConnection e Jwt__SigningKey, ou user-secrets);
    /// nunca são versionados. Sem chave JWT válida a aplicação não inicia.
    /// </summary>
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<ICurrentUser, SystemCurrentUser>();
        services.AddScoped<AuditSaveChangesInterceptor>();

        services.AddSingleton(JwtSettings.FromConfiguration(configuration));
        services.AddSingleton<ITokenService, TokenService>();
        services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();

        var nvd = configuration.GetSection(NvdOptions.SectionName).Get<NvdOptions>() ?? new NvdOptions();
        nvd.Validate();
        services.AddSingleton(nvd);
        services.AddMemoryCache();
        services.AddSingleton<NvdGate>();
        services.AddHttpClient<ICveLookup, NvdClient>((_, client) =>
        {
            client.Timeout = TimeSpan.FromSeconds(nvd.TimeoutSeconds);
            client.MaxResponseContentBufferSize = 2 * 1024 * 1024;
            client.DefaultRequestHeaders.UserAgent.ParseAdd("SentinelForge/1.0");
            client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        });

        var connectionString = configuration.GetConnectionString(ConnectionStringName);

        if (!string.IsNullOrWhiteSpace(connectionString))
        {
            services.AddDbContext<SentinelForgeDbContext>((sp, options) => options
                .UseNpgsql(connectionString)
                .AddInterceptors(sp.GetRequiredService<AuditSaveChangesInterceptor>()));

            services.AddScoped<IUnitOfWork, UnitOfWork>();
            services.AddScoped<IUserRepository, UserRepository>();
            services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
            services.AddScoped<IApplicationRepository, ApplicationRepository>();
            services.AddScoped<IVulnerabilityRepository, VulnerabilityRepository>();
            services.AddScoped<IAuditLogRepository, AuditLogRepository>();
        }

        return services;
    }
}

