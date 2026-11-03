using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SentinelForge.Infrastructure.Persistence;

/// <summary>
/// Usada apenas pelas ferramentas do EF (dotnet ef). A connection string vem da variável de ambiente
/// ConnectionStrings__DefaultConnection; sem ela só é possível gerar migrações, não aplicá-las.
/// </summary>
internal sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<SentinelForgeDbContext>
{
    public SentinelForgeDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable($"ConnectionStrings__{DependencyInjection.ConnectionStringName}")
            ?? "Host=localhost;Database=sentinelforge_design";

        var options = new DbContextOptionsBuilder<SentinelForgeDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new SentinelForgeDbContext(options);
    }
}
