using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Routing;
using SentinelForge.Api.Cli;
using SentinelForge.Api.Endpoints;
using SentinelForge.Api.Http;
using SentinelForge.Api.Security;
using SentinelForge.Application;
using SentinelForge.Application.Abstractions;
using SentinelForge.Infrastructure;
using SentinelForge.Infrastructure.Security;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// --- Serviços ---------------------------------------------------------------------------------------------
builder.Services.AddOpenApi();
builder.Services.AddHealthChecks();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUser, HttpContextCurrentUser>();

builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false)));

builder.Services.AddApplication(
    config.GetSection("Auth").Get<AuthOptions>() ?? new AuthOptions(),
    config.GetSection("Vulnerabilities").Get<VulnerabilityOptions>() ?? new VulnerabilityOptions());
builder.Services.AddInfrastructure(config);
builder.Services.AddJwtAuthentication(JwtSettings.FromConfiguration(config));

// Seguro por padrão: todo endpoint exige autenticação, salvo os marcados com AllowAnonymous.
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
    .AddPolicy(Policies.Administrator, p => p.RequireRole(nameof(SentinelForge.Domain.Enums.UserRole.Administrator)));

builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

var rate = config.GetSection("RateLimiting");
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    static string Key(HttpContext c) => c.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    // Limite estrito para endpoints de autenticação (brute force / credential stuffing), por IP.
    options.AddPolicy(AuthEndpoints.RateLimitPolicy, c => RateLimitPartition.GetFixedWindowLimiter(Key(c), _ => new FixedWindowRateLimiterOptions
    {
        PermitLimit = rate.GetValue("AuthPermitLimit", 10),
        Window = TimeSpan.FromSeconds(rate.GetValue("AuthWindowSeconds", 60)),
        QueueLimit = 0,
    }));

    // Consulta CVE (consome a cota da API externa): limite próprio e mais estrito, por IP.
    options.AddPolicy(VulnerabilityEndpoints.CveRateLimitPolicy, c => RateLimitPartition.GetFixedWindowLimiter(Key(c), _ => new FixedWindowRateLimiterOptions
    {
        PermitLimit = rate.GetValue("CvePermitLimit", 20),
        Window = TimeSpan.FromSeconds(rate.GetValue("CveWindowSeconds", 60)),
        QueueLimit = 0,
    }));

    // Limite geral por IP para o restante da API.
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(c => RateLimitPartition.GetFixedWindowLimiter(Key(c), _ => new FixedWindowRateLimiterOptions
    {
        PermitLimit = rate.GetValue("GlobalPermitLimit", 300),
        Window = TimeSpan.FromSeconds(rate.GetValue("GlobalWindowSeconds", 60)),
        QueueLimit = 0,
    }));
});

// CORS restritivo: sem origens configuradas, nenhuma origem externa é permitida.
var origins = config.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
builder.Services.AddCors(options =>
{
    if (origins.Length > 0)
    {
        options.AddDefaultPolicy(p => p
            .WithOrigins(origins)
            .WithMethods("GET", "POST", "PUT", "PATCH")
            .WithHeaders("Authorization", "Content-Type", "X-Token-Delivery")
            .AllowCredentials());
    }
});

var app = builder.Build();

// --- Comando administrativo (não sobe o servidor) -----------------------------------------------------------
if (args.Length > 0 && args[0] == AdminCli.Command)
{
    return await AdminCli.RunAsync(app.Services, args);
}

// --- Pipeline -----------------------------------------------------------------------------------------------
app.UseExceptionHandler();
app.UseStatusCodePages();

if (!app.Environment.IsDevelopment())
{
    // HTTPS obrigatório fora de desenvolvimento.
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers["X-Content-Type-Options"] = "nosniff";
    headers["X-Frame-Options"] = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    if (context.Request.Path.StartsWithSegments("/api", StringComparison.Ordinal))
    {
        headers.CacheControl = "no-store";
    }

    await next();
});

// UI do Swagger (apenas em desenvolvimento) fica antes da autenticação: são arquivos estáticos, sem endpoint,
// e a política de fallback (tudo exige login) os bloquearia.
if (app.Environment.IsDevelopment())
{
    app.UseSwaggerUI(options => options.SwaggerEndpoint("/openapi/v1.json", "SentinelForge API v1"));
}

app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().AllowAnonymous();
}

app.MapHealthChecks("/health").WithMetadata(new HttpMethodMetadata(["GET"])).AllowAnonymous();
app.MapAuthEndpoints();
app.MapUserEndpoints();
app.MapResourceEndpoints();
app.MapVulnerabilityEndpoints();

await app.RunAsync();
return 0;

/// <summary>Ponto de entrada exposto para os testes de integração (WebApplicationFactory).</summary>
public partial class Program;


