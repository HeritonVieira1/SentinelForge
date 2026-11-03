using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using SentinelForge.Application.Abstractions;
using SentinelForge.Infrastructure;
using SentinelForge.Infrastructure.Persistence;

namespace SentinelForge.IntegrationTests.Persistence;

/// <summary>
/// Cria um banco PostgreSQL isolado e descartável por execução, aplica as migrações reais e o remove ao final.
/// Requer a variável de ambiente ConnectionStrings__DefaultConnection apontando para um servidor com permissão CREATEDB.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private const string EnvironmentVariable = "ConnectionStrings__DefaultConnection";

    private NpgsqlConnectionStringBuilder _admin = null!;
    private string _databaseName = null!;
    private string _testConnectionString = null!;

    public async Task InitializeAsync()
    {
        var baseConnection = Environment.GetEnvironmentVariable(EnvironmentVariable);
        if (string.IsNullOrWhiteSpace(baseConnection))
        {
            throw new InvalidOperationException(
                $"Defina a variável de ambiente {EnvironmentVariable} para executar os testes de integração com PostgreSQL.");
        }

        _admin = new NpgsqlConnectionStringBuilder(baseConnection) { Database = "postgres", Pooling = false };
        _databaseName = $"sentinelforge_test_{Guid.NewGuid():N}";
        _testConnectionString = new NpgsqlConnectionStringBuilder(baseConnection) { Database = _databaseName }.ConnectionString;

        await using (var connection = new NpgsqlConnection(_admin.ConnectionString))
        {
            await connection.OpenAsync();
            await using var create = new NpgsqlCommand($"CREATE DATABASE \"{_databaseName}\"", connection);
            await create.ExecuteNonQueryAsync();
        }

        await using var context = CreateContext();
        await context.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        await using var connection = new NpgsqlConnection(_admin.ConnectionString);
        await connection.OpenAsync();
        await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{_databaseName}\" WITH (FORCE)", connection);
        await drop.ExecuteNonQueryAsync();
    }

    /// <summary>Cria um DbContext (com auditoria) usando o registro real de DI da infraestrutura.</summary>
    public SentinelForgeDbContext CreateContext(ICurrentUser? currentUser = null)
    {
        var services = new ServiceCollection();
        if (currentUser is not null)
        {
            services.AddSingleton(currentUser);
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"ConnectionStrings:{DependencyInjection.ConnectionStringName}"] = _testConnectionString,
            })
            .Build();

        services.AddInfrastructure(configuration);
        var provider = services.BuildServiceProvider();
        return provider.CreateScope().ServiceProvider.GetRequiredService<SentinelForgeDbContext>();
    }
}

[CollectionDefinition(Name)]
public sealed class PostgresTestGroup : ICollectionFixture<PostgresFixture>
{
    public const string Name = "postgres";
}

public sealed class FakeCurrentUser(Guid? userId, string? ipAddress) : ICurrentUser
{
    public Guid? UserId { get; } = userId;

    public string? IpAddress { get; } = ipAddress;
}

