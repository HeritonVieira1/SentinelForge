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

    private readonly List<string> _extraDatabases = [];
    private NpgsqlConnectionStringBuilder _admin = null!;
    private string _baseConnection = null!;
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

        _baseConnection = baseConnection;
        JwtKey = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(48));
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

        // Rede de segurança: qualquer host criado pelos testes que leia o ambiente enxerga o banco de TESTE,
        // nunca o banco configurado pelo desenvolvedor.
        Environment.SetEnvironmentVariable(EnvironmentVariable, _testConnectionString);
        Environment.SetEnvironmentVariable("Jwt__SigningKey", JwtKey);
    }

    public string ConnectionString => _testConnectionString;

    public string JwtKey { get; private set; } = null!;

    /// <summary>Cria um banco vazio e migrado, descartado ao final da execução.</summary>
    public async Task<string> CreateExtraDatabaseAsync()
    {
        var name = $"sentinelforge_test_{Guid.NewGuid():N}";
        var cs = new NpgsqlConnectionStringBuilder(_baseConnection) { Database = name }.ConnectionString;

        await using (var connection = new NpgsqlConnection(_admin.ConnectionString))
        {
            await connection.OpenAsync();
            await using var create = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", connection);
            await create.ExecuteNonQueryAsync();
        }

        _extraDatabases.Add(name);
        await using var context = CreateContext(connectionString: cs);
        await context.Database.MigrateAsync();
        return cs;
    }

    public async Task DisposeAsync()
    {
        NpgsqlConnection.ClearAllPools();
        await using var connection = new NpgsqlConnection(_admin.ConnectionString);
        await connection.OpenAsync();
        await using var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{_databaseName}\" WITH (FORCE)", connection);
        await drop.ExecuteNonQueryAsync();

        foreach (var extra in _extraDatabases)
        {
            await using var dropExtra = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{extra}\" WITH (FORCE)", connection);
            await dropExtra.ExecuteNonQueryAsync();
        }
    }

    /// <summary>Cria um DbContext (com auditoria) usando o registro real de DI da infraestrutura.</summary>
    public SentinelForgeDbContext CreateContext(ICurrentUser? currentUser = null, string? connectionString = null)
    {
        var services = new ServiceCollection();
        if (currentUser is not null)
        {
            services.AddSingleton(currentUser);
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"ConnectionStrings:{DependencyInjection.ConnectionStringName}"] = connectionString ?? _testConnectionString,
                ["Jwt:Issuer"] = "SentinelForge",
                ["Jwt:Audience"] = "SentinelForge.Api",
                ["Jwt:SigningKey"] = JwtKey,
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

    public SentinelForge.Domain.Enums.UserRole? Role => null;

    public string? IpAddress { get; } = ipAddress;
}


