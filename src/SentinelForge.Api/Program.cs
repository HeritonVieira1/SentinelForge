using Microsoft.AspNetCore.Routing;
using SentinelForge.Api.Security;
using SentinelForge.Application.Abstractions;
using SentinelForge.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddHealthChecks();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUser, HttpContextCurrentUser>();
builder.Services.AddInfrastructure(builder.Configuration);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI(options => options.SwaggerEndpoint("/openapi/v1.json", "SentinelForge API v1"));
    app.UseHttpsRedirection();
}

app.MapHealthChecks("/health").WithMetadata(new HttpMethodMetadata(["GET"]));

await app.RunAsync();

/// <summary>Ponto de entrada exposto para os testes de integração (WebApplicationFactory).</summary>
public partial class Program;

