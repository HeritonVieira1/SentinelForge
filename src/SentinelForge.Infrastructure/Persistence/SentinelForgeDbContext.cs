using Microsoft.EntityFrameworkCore;
using SentinelForge.Domain.Entities;
using DomainApplication = SentinelForge.Domain.Entities.Application;

namespace SentinelForge.Infrastructure.Persistence;

/// <summary>Contexto do Entity Framework Core (PostgreSQL).</summary>
public sealed class SentinelForgeDbContext(DbContextOptions<SentinelForgeDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();

    public DbSet<DomainApplication> Applications => Set<DomainApplication>();

    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();

    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(SentinelForgeDbContext).Assembly);
    }
}
