using Microsoft.Extensions.DependencyInjection;
using SentinelForge.Application.Services;

namespace SentinelForge.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services, AuthOptions options, VulnerabilityOptions vulnerabilityOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(vulnerabilityOptions);

        services.AddSingleton(options);
        services.AddSingleton(vulnerabilityOptions);
        services.AddScoped<AuthService>();
        services.AddScoped<UserService>();
        services.AddScoped<AdminProvisioningService>();
        services.AddScoped<ApplicationsService>();
        services.AddScoped<VulnerabilitiesService>();
        services.AddScoped<AuditService>();
        services.AddScoped<CveService>();
        return services;
    }
}

