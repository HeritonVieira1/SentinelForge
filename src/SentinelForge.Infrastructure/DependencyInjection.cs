using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SentinelForge.Application.Abstractions;
using SentinelForge.Infrastructure.Auditing;
using SentinelForge.Infrastructure.Persistence;

namespace SentinelForge.Infrastructure;

public static class DependencyInjection
{
    public const string ConnectionStringName = "DefaultConnection";

    /// <summary>
    /// Registra a infraestrutura. A connection string é lida de ConnectionStrings:DefaultConnection
    /// (variável de ambiente ConnectionStrings__DefaultConnection ou user-secrets); nunca é versionada.
    /// Sem ela o DbContext não é registrado, o que permite subir a API apenas com /health.
    /// </summary>
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<ICurrentUser, SystemCurrentUser>();
        services.AddScoped<AuditSaveChangesInterceptor>();

        var connectionString = configuration.GetConnectionString(ConnectionStringName);

        if (!string.IsNullOrWhiteSpace(connectionString))
        {
            services.AddDbContext<SentinelForgeDbContext>((sp, options) => options
                .UseNpgsql(connectionString)
                .AddInterceptors(sp.GetRequiredService<AuditSaveChangesInterceptor>()));
        }

        return services;
    }
}
