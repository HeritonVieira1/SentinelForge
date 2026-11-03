using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;
using SentinelForge.Domain.ValueObjects;
using SentinelForge.IntegrationTests.Persistence;
using DomainApplication = SentinelForge.Domain.Entities.Application;

namespace SentinelForge.IntegrationTests.Security;

public sealed record UserView(Guid Id, string Name, string Email, string Role, bool IsActive);

public sealed record TokenView(string AccessToken, string TokenType, DateTime ExpiresAt, DateTime RefreshTokenExpiresAt, string? RefreshToken);

public sealed record Session(Guid Id, string Email, string AccessToken, string RefreshToken)
{
    public HttpClient Client { get; init; } = null!;
}

/// <summary>Sobe a API real (em memória) apontando para o banco de TESTE isolado e com chave JWT aleatória.</summary>
public sealed class ApiFactory : WebApplicationFactory<Program>
{
    private readonly Dictionary<string, string?> _settings;

    private readonly Action<IServiceCollection>? _configureServices;

    public ApiFactory(string? connectionString, string jwtKey, Dictionary<string, string?>? overrides = null, Action<IServiceCollection>? configureServices = null)
    {
        _configureServices = configureServices;
        _settings = new Dictionary<string, string?>
        {
            ["Jwt:SigningKey"] = jwtKey,
            ["RateLimiting:AuthPermitLimit"] = "100000",
            ["RateLimiting:GlobalPermitLimit"] = "100000",
        };

        if (connectionString is not null)
        {
            _settings["ConnectionStrings:DefaultConnection"] = connectionString;
        }

        if (overrides is not null)
        {
            foreach (var (key, value) in overrides)
            {
                _settings[key] = value;
            }
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        foreach (var (key, value) in _settings)
        {
            builder.UseSetting(key, value);
        }

        if (_configureServices is not null)
        {
            builder.ConfigureTestServices(_configureServices);
        }
    }
}

/// <summary>Contexto de um teste: API em memória + helpers para criar usuários, sessões e dados.</summary>
public sealed class ApiContext : IDisposable
{
    public const string StrongPassword = "Str0ng!Passw0rd#2026";

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly string _connection;

    public ApiContext(PostgresFixture db, Dictionary<string, string?>? overrides = null, Action<IServiceCollection>? configureServices = null, string? connectionString = null)
    {
        Db = db;
        _connection = connectionString ?? db.ConnectionString;
        Factory = new ApiFactory(_connection, db.JwtKey, overrides, configureServices);
        Client = NewClient();
    }

    public PostgresFixture Db { get; }

    public ApiFactory Factory { get; }

    public HttpClient Client { get; }

    public static string NewEmail() => $"{Guid.NewGuid():N}@example.com";

    public HttpClient NewClient(string? bearer = null)
    {
        var client = Factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false });
        if (bearer is not null)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }

        return client;
    }

    public async Task<UserView> RegisterAsync(string? email = null, string password = StrongPassword, string name = "Usuário Teste")
    {
        using var response = await Client.PostAsJsonAsync("/api/auth/register", new { name, email = email ?? NewEmail(), password });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<UserView>(Json))!;
    }

    public async Task<HttpResponseMessage> LoginRawAsync(string email, string password, bool refreshInBody = true)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login")
        {
            Content = JsonContent.Create(new { email, password }),
        };
        if (refreshInBody)
        {
            request.Headers.Add("X-Token-Delivery", "body");
        }

        return await Client.SendAsync(request);
    }

    public async Task<TokenView> LoginAsync(string email, string password = StrongPassword)
    {
        using var response = await LoginRawAsync(email, password);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TokenView>(Json))!;
    }

    public async Task SetRoleAsync(Guid userId, UserRole role)
    {
        await using var db = Db.CreateContext(connectionString: _connection);
        var user = await db.Users.SingleAsync(u => u.Id == userId);
        user.ChangeRole(role, DateTime.UtcNow);
        await db.SaveChangesAsync();
    }

    /// <summary>Cadastra, define o papel diretamente no banco (o cliente nunca escolhe) e faz login.</summary>
    public async Task<Session> NewSessionAsync(UserRole role = UserRole.Developer)
    {
        var user = await RegisterAsync();
        if (role != UserRole.Developer)
        {
            await SetRoleAsync(user.Id, role);
        }

        var tokens = await LoginAsync(user.Email);
        return new Session(user.Id, user.Email, tokens.AccessToken, tokens.RefreshToken!) { Client = NewClient(tokens.AccessToken) };
    }

    public async Task<(Guid AppId, Guid VulnId)> SeedAsync(Guid ownerId, Guid? assignedUserId = null)
    {
        var appId = await SeedApplicationAsync(ownerId);
        var vulnId = await SeedVulnerabilityAsync(appId, ownerId, assignedUserId);
        return (appId, vulnId);
    }

    public async Task<Guid> SeedApplicationAsync(Guid ownerId, string? name = null)
    {
        await using var db = Db.CreateContext(connectionString: _connection);
        var app = DomainApplication.Create(name ?? "App " + Guid.NewGuid().ToString("N")[..6], "desc", null, ownerId, DateTime.UtcNow);
        db.Applications.Add(app);
        await db.SaveChangesAsync();
        return app.Id;
    }

    public async Task<Guid> SeedVulnerabilityAsync(
        Guid appId, Guid createdBy, Guid? assignedUserId = null, string title = "XSS", decimal? score = 5.5m, string category = "Injection", DateTime? discoveredAt = null)
    {
        await using var db = Db.CreateContext(connectionString: _connection);
        var cvss = score is { } s ? CvssRating.Create(s, CvssVersion.V40) : null;
        var vuln = Vulnerability.Create(title, "desc", category, null, "Encode output", cvss, discoveredAt ?? DateTime.UtcNow.AddDays(-1), appId, assignedUserId, createdBy, DateTime.UtcNow);
        db.Vulnerabilities.Add(vuln);
        await db.SaveChangesAsync();
        return vuln.Id;
    }

    public Task AdvanceAsync(Guid vulnId, Guid actorId, params VulnerabilityStatus[] path) => AdvanceAtAsync(vulnId, actorId, DateTime.UtcNow, path);

    /// <summary>Leva a vulnerabilidade a um status seguindo o workflow, registrando <paramref name="actorId"/> como autor.</summary>
    public async Task AdvanceAtAsync(Guid vulnId, Guid actorId, DateTime at, params VulnerabilityStatus[] path)
    {
        await using var db = Db.CreateContext(connectionString: _connection);
        var vuln = await db.Vulnerabilities.SingleAsync(v => v.Id == vulnId);
        foreach (var step in path)
        {
            vuln.ChangeStatus(step, actorId, at, step == VulnerabilityStatus.AcceptedRisk ? "justificativa de teste" : null);
        }

        await db.SaveChangesAsync();
    }
    /// <summary>Gera um JWT arbitrário (para testar expirado, chave errada, sessão inexistente etc.).</summary>
    public string ForgeToken(
        string? signingKey = null,
        TimeSpan? lifetime = null,
        Guid? userId = null,
        string role = "Administrator",
        Guid? sessionId = null,
        bool withoutSignature = false)
    {
        var now = DateTime.UtcNow;
        var life = lifetime ?? TimeSpan.FromMinutes(10);
        var claims = new Dictionary<string, object>
        {
            ["sub"] = (userId ?? Guid.NewGuid()).ToString(),
            ["role"] = role,
            ["sid"] = (sessionId ?? Guid.NewGuid()).ToString(),
            ["jti"] = Guid.NewGuid().ToString(),
        };

        var handler = new JsonWebTokenHandler();
        if (withoutSignature)
        {
            claims["iss"] = "SentinelForge";
            claims["aud"] = "SentinelForge.Api";
            claims["exp"] = new DateTimeOffset(now.Add(life)).ToUnixTimeSeconds();
            return handler.CreateToken(JsonSerializer.Serialize(claims));
        }

        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(signingKey ?? Db.JwtKey));
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "SentinelForge",
            Audience = "SentinelForge.Api",
            NotBefore = life < TimeSpan.Zero ? now.Add(life).AddMinutes(-10) : now,
            Expires = now.Add(life),
            IssuedAt = life < TimeSpan.Zero ? now.Add(life).AddMinutes(-10) : now,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
            Claims = claims,
        });
    }

    public void Dispose()
    {
        Client.Dispose();
        Factory.Dispose();
    }
}



