using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SentinelForge.Domain.Enums;
using SentinelForge.IntegrationTests.Persistence;

namespace SentinelForge.IntegrationTests.Security;

[Collection(PostgresTestGroup.Name)]
public sealed class AuthorizationTests(PostgresFixture db) : IDisposable
{
    private readonly ApiContext _api = new(db);

    public void Dispose() => _api.Dispose();

    private static Uri Url(string path) => new(path, UriKind.Relative);

    private static Task<HttpResponseMessage> PutRoleAsync(HttpClient client, Guid userId, string role) =>
        client.PutAsJsonAsync($"/api/users/{userId}/role", new { role });

    // ---------- RBAC por perfil ----------

    [Fact]
    public async Task AdministrativeEndpoints_AreDenied_ToDeveloperAndSecurityAnalyst()
    {
        var developer = await _api.NewSessionAsync();
        var analyst = await _api.NewSessionAsync(UserRole.SecurityAnalyst);

        foreach (var session in new[] { developer, analyst })
        {
            using var users = await session.Client.GetAsync(Url("/api/users"));
            using var audit = await session.Client.GetAsync(Url("/api/audit-logs"));
            using var role = await PutRoleAsync(session.Client, developer.Id, "SecurityAnalyst");
            using var revoke = await session.Client.PostAsync(Url($"/api/users/{developer.Id}/revoke-sessions"), content: null);

            Assert.Equal(HttpStatusCode.Forbidden, users.StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, audit.StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, role.StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, revoke.StatusCode);
        }
    }

    [Fact]
    public async Task Administrator_CanListUsers_AndAuditLogs_WithoutLeakingHashes()
    {
        var admin = await _api.NewSessionAsync(UserRole.Administrator);

        using var users = await admin.Client.GetAsync(Url("/api/users?pageSize=5"));
        using var audit = await admin.Client.GetAsync(Url($"/api/audit-logs?entityId={admin.Id}"));
        var usersBody = await users.Content.ReadAsStringAsync();
        var auditBody = await audit.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, users.StatusCode);
        Assert.Equal(HttpStatusCode.OK, audit.StatusCode);
        Assert.DoesNotContain("passwordHash", usersBody, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("AQAAAA", auditBody, StringComparison.Ordinal);
        Assert.Contains("LoginSucceeded", auditBody, StringComparison.Ordinal);
    }

    // ---------- Elevação de privilégio ----------

    [Fact]
    public async Task Developer_CannotElevateOwnRole()
    {
        var developer = await _api.NewSessionAsync();

        using var response = await PutRoleAsync(developer.Client, developer.Id, "Administrator");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        await using var read = db.CreateContext();
        Assert.Equal(UserRole.Developer, (await read.Users.AsNoTracking().SingleAsync(u => u.Id == developer.Id)).Role);
    }

    [Fact]
    public async Task Developer_CannotElevateAnotherUser()
    {
        var developer = await _api.NewSessionAsync();
        var other = await _api.NewSessionAsync();

        using var response = await PutRoleAsync(developer.Client, other.Id, "Administrator");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Administrator_CannotChangeOwnRole()
    {
        var admin = await _api.NewSessionAsync(UserRole.Administrator);

        using var response = await PutRoleAsync(admin.Client, admin.Id, "Developer");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("Root")]
    [InlineData("99")]
    [InlineData("")]
    public async Task ChangeRole_WithInvalidRole_IsRejected(string role)
    {
        var admin = await _api.NewSessionAsync(UserRole.Administrator);
        var target = await _api.NewSessionAsync();

        using var response = await PutRoleAsync(admin.Client, target.Id, role);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ChangeRole_ByAdministrator_IsAudited_AndInvalidatesTargetSessions()
    {
        var admin = await _api.NewSessionAsync(UserRole.Administrator);
        var target = await _api.NewSessionAsync();

        using var response = await PutRoleAsync(admin.Client, target.Id, "SecurityAnalyst");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await using var read = db.CreateContext();
        Assert.Equal(UserRole.SecurityAnalyst, (await read.Users.AsNoTracking().SingleAsync(u => u.Id == target.Id)).Role);

        var updates = await read.AuditLogs.AsNoTracking()
            .Where(a => a.EntityId == target.Id && a.Action == AuditAction.Updated)
            .ToListAsync();
        var audit = Assert.Single(updates, a => a.NewValues!.Contains("SecurityAnalyst", StringComparison.Ordinal));
        Assert.Equal(admin.Id, audit.UserId); // quem fez a alteração
        using (var oldValues = JsonDocument.Parse(audit.OldValues!))
        {
            Assert.Equal("Developer", oldValues.RootElement.GetProperty("Role").GetString());
        }

        // O token antigo (papel Developer) e a sessão anterior deixam de valer imediatamente.
        using var oldAccess = await target.Client.GetAsync(Url("/api/applications"));
        using var oldRefresh = await _api.Client.PostAsJsonAsync("/api/auth/refresh", new { refreshToken = target.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, oldAccess.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, oldRefresh.StatusCode);
    }

    [Fact]
    public async Task RevokeSessions_ByAdministrator_ForcesReauthentication()
    {
        var admin = await _api.NewSessionAsync(UserRole.Administrator);
        var target = await _api.NewSessionAsync();

        using var response = await admin.Client.PostAsync(Url($"/api/users/{target.Id}/revoke-sessions"), content: null);
        using var access = await target.Client.GetAsync(Url("/api/applications"));
        using var refresh = await _api.Client.PostAsJsonAsync("/api/auth/refresh", new { refreshToken = target.RefreshToken });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, access.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);
    }

    [Fact]
    public async Task DeactivatedUser_LosesAccessImmediately()
    {
        var target = await _api.NewSessionAsync();
        await using (var write = db.CreateContext())
        {
            var user = await write.Users.SingleAsync(u => u.Id == target.Id);
            user.Deactivate(DateTime.UtcNow);
            await write.SaveChangesAsync();
        }

        using var access = await target.Client.GetAsync(Url("/api/applications"));
        using var login = await _api.LoginRawAsync(target.Email, ApiContext.StrongPassword);

        Assert.Equal(HttpStatusCode.Unauthorized, access.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
    }

    // ---------- IDOR / propriedade de recursos ----------

    [Fact]
    public async Task Users_CanReadOnlyThemselves_ExceptAdministrators()
    {
        var alice = await _api.NewSessionAsync();
        var bob = await _api.NewSessionAsync();
        var admin = await _api.NewSessionAsync(UserRole.Administrator);

        using var own = await alice.Client.GetAsync(Url($"/api/users/{alice.Id}"));
        using var others = await alice.Client.GetAsync(Url($"/api/users/{bob.Id}"));
        using var asAdmin = await admin.Client.GetAsync(Url($"/api/users/{bob.Id}"));

        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, others.StatusCode); // 404, não 403: não revela que o id existe
        Assert.Equal(HttpStatusCode.OK, asAdmin.StatusCode);
    }

    [Fact]
    public async Task Developer_CannotAccessApplicationsOrVulnerabilities_OfAnotherUser()
    {
        var owner = await _api.NewSessionAsync();
        var intruder = await _api.NewSessionAsync();
        var (appId, vulnId) = await _api.SeedAsync(owner.Id);

        using var app = await intruder.Client.GetAsync(Url($"/api/applications/{appId}"));
        using var vulns = await intruder.Client.GetAsync(Url($"/api/applications/{appId}/vulnerabilities"));
        using var vuln = await intruder.Client.GetAsync(Url($"/api/vulnerabilities/{vulnId}"));
        using var patch = await intruder.Client.PatchAsJsonAsync($"/api/vulnerabilities/{vulnId}/status", new { status = "Resolved" });
        using var list = await intruder.Client.GetAsync(Url("/api/applications?pageSize=100"));

        Assert.Equal(HttpStatusCode.NotFound, app.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, vulns.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, vuln.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, patch.StatusCode);
        Assert.DoesNotContain(appId.ToString(), await list.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        await using var read = db.CreateContext();
        Assert.Equal(VulnerabilityStatus.New, (await read.Vulnerabilities.AsNoTracking().SingleAsync(v => v.Id == vulnId)).Status);
    }

    [Fact]
    public async Task Developer_CanAccess_OwnedApplications_AndThoseWithAssignedVulnerabilities()
    {
        var owner = await _api.NewSessionAsync();
        var assignee = await _api.NewSessionAsync();
        var (appId, vulnId) = await _api.SeedAsync(owner.Id, assignee.Id);

        foreach (var session in new[] { owner, assignee })
        {
            using var app = await session.Client.GetAsync(Url($"/api/applications/{appId}"));
            using var vuln = await session.Client.GetAsync(Url($"/api/vulnerabilities/{vulnId}"));
            Assert.Equal(HttpStatusCode.OK, app.StatusCode);
            Assert.Equal(HttpStatusCode.OK, vuln.StatusCode);
        }
    }

    [Fact]
    public async Task SecurityAnalyst_CanSeeEverything()
    {
        var owner = await _api.NewSessionAsync();
        var analyst = await _api.NewSessionAsync(UserRole.SecurityAnalyst);
        var (appId, vulnId) = await _api.SeedAsync(owner.Id);

        using var app = await analyst.Client.GetAsync(Url($"/api/applications/{appId}"));
        using var vuln = await analyst.Client.GetAsync(Url($"/api/vulnerabilities/{vulnId}"));

        Assert.Equal(HttpStatusCode.OK, app.StatusCode);
        Assert.Equal(HttpStatusCode.OK, vuln.StatusCode);
    }
}

