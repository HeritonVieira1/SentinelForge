using SentinelForge.Api.Http;
using SentinelForge.Api.Security;
using SentinelForge.Application.Services;

namespace SentinelForge.Api.Endpoints;

internal static class ResourceEndpoints
{
    public static IEndpointRouteBuilder MapResourceEndpoints(this IEndpointRouteBuilder app)
    {
        var apps = app.MapGroup("/api/applications").WithTags("Applications");

        apps.MapGet("/", async (ApplicationsService svc, CancellationToken ct, int page = 1, int pageSize = 20) =>
            (await svc.ListAsync(page, pageSize, ct)).ToHttp());

        apps.MapGet("/{id:guid}", async (Guid id, ApplicationsService svc, CancellationToken ct) =>
            (await svc.GetAsync(id, ct)).ToHttp());

        apps.MapGet("/{id:guid}/vulnerabilities", async (Guid id, ApplicationsService svc, CancellationToken ct, int page = 1, int pageSize = 20) =>
            (await svc.ListVulnerabilitiesAsync(id, page, pageSize, ct)).ToHttp());

        app.MapGet("/api/audit-logs", async (AuditService svc, CancellationToken ct, int page = 1, int pageSize = 20, string? entityName = null, Guid? entityId = null) =>
            (await svc.ListAsync(page, pageSize, entityName, entityId, ct)).ToHttp())
            .RequireAuthorization(Policies.Administrator)
            .WithTags("Audit");

        return app;
    }
}

