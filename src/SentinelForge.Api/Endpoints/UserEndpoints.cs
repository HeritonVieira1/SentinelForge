using SentinelForge.Api.Http;
using SentinelForge.Api.Security;
using SentinelForge.Application.Services;

namespace SentinelForge.Api.Endpoints;

internal static class UserEndpoints
{
    public static IEndpointRouteBuilder MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/users").WithTags("Users");

        group.MapGet("/", async (UserService users, CancellationToken ct, int page = 1, int pageSize = 20) =>
            (await users.ListAsync(page, pageSize, ct)).ToHttp())
            .RequireAuthorization(Policies.Administrator);

        // Autorização por recurso: administradores veem qualquer usuário; os demais, só a si mesmos.
        group.MapGet("/{id:guid}", async (Guid id, UserService users, CancellationToken ct) =>
            (await users.GetAsync(id, ct)).ToHttp());

        group.MapPut("/{id:guid}/role", async (Guid id, ChangeRoleRequest request, UserService users, CancellationToken ct) =>
            (await users.ChangeRoleAsync(id, request.Role, ct)).ToHttp())
            .RequireAuthorization(Policies.Administrator);

        group.MapPost("/{id:guid}/revoke-sessions", async (Guid id, UserService users, CancellationToken ct) =>
            (await users.RevokeSessionsAsync(id, ct)).ToHttp())
            .RequireAuthorization(Policies.Administrator);

        return app;
    }
}
