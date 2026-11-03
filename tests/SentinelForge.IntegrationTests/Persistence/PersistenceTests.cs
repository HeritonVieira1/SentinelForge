using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;
using DomainApplication = SentinelForge.Domain.Entities.Application;

namespace SentinelForge.IntegrationTests.Persistence;

[Collection(PostgresTestGroup.Name)]
public sealed class PersistenceTests(PostgresFixture fixture)
{
    private const string FakeHash = "hash-opaco-de-teste";

    private static User NewUser(string? email = null) =>
        User.Create("Ana Teste", email ?? $"{Guid.NewGuid():N}@example.com", FakeHash, UserRole.Analyst, DateTime.UtcNow);

    private static DomainApplication NewApp(Guid ownerId) =>
        DomainApplication.Create("Portal", "desc", "https://github.com/org/repo", ownerId, DateTime.UtcNow);

    private static Vulnerability NewVuln(Guid appId, Guid? assignee = null) =>
        Vulnerability.Create("SQL Injection", "desc", Severity.High, "Injection", "CVE-2024-12345", "Parametrizar", DateTime.UtcNow, appId, assignee);

    private static async Task<(User User, DomainApplication App, Vulnerability Vuln)> SeedAsync(PostgresFixture f)
    {
        await using var db = f.CreateContext();
        var user = NewUser();
        db.Users.Add(user);
        await db.SaveChangesAsync();
        var app = NewApp(user.Id);
        db.Applications.Add(app);
        await db.SaveChangesAsync();
        var vuln = NewVuln(app.Id, user.Id);
        db.Vulnerabilities.Add(vuln);
        await db.SaveChangesAsync();
        return (user, app, vuln);
    }

    [Fact]
    public async Task User_IsPersisted_WithUtcDatesAndHashOnly()
    {
        var user = NewUser();
        await using (var db = fixture.CreateContext())
        {
            db.Users.Add(user);
            await db.SaveChangesAsync();
        }

        await using var read = fixture.CreateContext();
        var loaded = await read.Users.AsNoTracking().SingleAsync(u => u.Id == user.Id);

        Assert.Equal(user.Email, loaded.Email);
        Assert.Equal(UserRole.Analyst, loaded.Role);
        Assert.Equal(FakeHash, loaded.PasswordHash);
        Assert.True(loaded.IsActive);
        Assert.Equal(DateTimeKind.Utc, loaded.CreatedAt.Kind);
    }

    [Fact]
    public async Task Application_IsPersisted_AndLinkedToOwner()
    {
        var (user, app, _) = await SeedAsync(fixture);

        await using var read = fixture.CreateContext();
        var loaded = await read.Applications.AsNoTracking().Include(a => a.Owner).SingleAsync(a => a.Id == app.Id);

        Assert.Equal(user.Id, loaded.OwnerUserId);
        Assert.Equal(user.Email, loaded.Owner!.Email);
        Assert.Equal("https://github.com/org/repo", loaded.RepositoryUrl);
    }

    [Fact]
    public async Task Vulnerability_IsPersisted_WithRelationships()
    {
        var (user, app, vuln) = await SeedAsync(fixture);

        await using var read = fixture.CreateContext();
        var loadedApp = await read.Applications.AsNoTracking().Include(a => a.Vulnerabilities).SingleAsync(a => a.Id == app.Id);
        var loaded = Assert.Single(loadedApp.Vulnerabilities);

        Assert.Equal(vuln.Id, loaded.Id);
        Assert.Equal(Severity.High, loaded.Severity);
        Assert.Equal(VulnerabilityStatus.Open, loaded.Status);
        Assert.Equal("CVE-2024-12345", loaded.CveId);
        Assert.Equal(user.Id, loaded.AssignedUserId);
        Assert.Null(loaded.ResolvedAt);
    }

    [Fact]
    public async Task DuplicateEmail_IsRejectedByUniqueIndex()
    {
        var email = $"{Guid.NewGuid():N}@example.com";
        await using (var db = fixture.CreateContext())
        {
            db.Users.Add(NewUser(email));
            await db.SaveChangesAsync();
        }

        await using var second = fixture.CreateContext();
        second.Users.Add(NewUser(email.ToUpperInvariant()));

        var ex = await Assert.ThrowsAsync<DbUpdateException>(() => second.SaveChangesAsync());
        Assert.Equal(PostgresErrorCodes.UniqueViolation, Assert.IsType<PostgresException>(ex.InnerException).SqlState);
    }

    [Theory]
    [InlineData("UPDATE vulnerabilities SET \"Severity\" = {0} WHERE \"Id\" = {1}", "Extreme")]
    [InlineData("UPDATE vulnerabilities SET \"Status\" = {0} WHERE \"Id\" = {1}", "Banana")]
    public async Task Database_RejectsInvalidSeverityOrStatus(string sql, string value)
    {
        var (_, _, vuln) = await SeedAsync(fixture);
        await using var db = fixture.CreateContext();

        var ex = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(sql, value, vuln.Id));

        Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
    }

    [Fact]
    public async Task Database_RejectsResolvedStatusWithoutResolvedAt()
    {
        var (_, _, vuln) = await SeedAsync(fixture);
        await using var db = fixture.CreateContext();

        var ex = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(
            "UPDATE vulnerabilities SET \"Status\" = 'Resolved' WHERE \"Id\" = {0}", vuln.Id));

        Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
    }

    [Fact]
    public async Task ResolvingVulnerability_PersistsResolvedAt()
    {
        var (_, _, vuln) = await SeedAsync(fixture);
        await using (var db = fixture.CreateContext())
        {
            var tracked = await db.Vulnerabilities.SingleAsync(v => v.Id == vuln.Id);
            tracked.ChangeStatus(VulnerabilityStatus.Resolved, DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        await using var read = fixture.CreateContext();
        var loaded = await read.Vulnerabilities.AsNoTracking().SingleAsync(v => v.Id == vuln.Id);
        Assert.Equal(VulnerabilityStatus.Resolved, loaded.Status);
        Assert.NotNull(loaded.ResolvedAt);
    }

    [Fact]
    public async Task Creating_GeneratesAuditLog_WithActorAndIp_AndNeverStoresPasswordHash()
    {
        var actorId = (await SeedAsync(fixture)).User.Id;
        var user = NewUser();
        await using (var db = fixture.CreateContext(new FakeCurrentUser(actorId, "203.0.113.7")))
        {
            db.Users.Add(user);
            await db.SaveChangesAsync();
        }

        await using var read = fixture.CreateContext();
        var log = await read.AuditLogs.AsNoTracking().SingleAsync(a => a.EntityId == user.Id);

        Assert.Equal(AuditAction.Created, log.Action);
        Assert.Equal("User", log.EntityName);
        Assert.Equal(actorId, log.UserId);
        Assert.Equal("203.0.113.7", log.IpAddress);
        Assert.Null(log.OldValues);
        Assert.DoesNotContain(FakeHash, log.NewValues, StringComparison.Ordinal);
        using var json = JsonDocument.Parse(log.NewValues!);
        Assert.Equal("[REDACTED]", json.RootElement.GetProperty("PasswordHash").GetString());
        Assert.Equal(user.Email, json.RootElement.GetProperty("Email").GetString());
    }

    [Fact]
    public async Task Updating_GeneratesAuditLog_WithOnlyChangedValues_AsSystemEvent()
    {
        var (_, _, vuln) = await SeedAsync(fixture);
        await using (var db = fixture.CreateContext())
        {
            var tracked = await db.Vulnerabilities.SingleAsync(v => v.Id == vuln.Id);
            tracked.ChangeSeverity(Severity.Critical);
            await db.SaveChangesAsync();
        }

        await using var read = fixture.CreateContext();
        var log = await read.AuditLogs.AsNoTracking()
            .SingleAsync(a => a.EntityId == vuln.Id && a.Action == AuditAction.Updated);

        Assert.Null(log.UserId);
        Assert.Null(log.IpAddress);
        using var oldJson = JsonDocument.Parse(log.OldValues!);
        using var newJson = JsonDocument.Parse(log.NewValues!);
        Assert.Equal("High", oldJson.RootElement.GetProperty("Severity").GetString());
        Assert.Equal("Critical", newJson.RootElement.GetProperty("Severity").GetString());
        Assert.False(newJson.RootElement.TryGetProperty("Title", out _));
    }

    [Fact]
    public async Task PhysicalDeletion_OfAuditedEntity_IsBlocked()
    {
        var (_, app, _) = await SeedAsync(fixture);
        await using var db = fixture.CreateContext();
        var tracked = await db.Applications.SingleAsync(a => a.Id == app.Id);
        db.Applications.Remove(tracked);

        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task Database_RestrictsDeletionOfReferencedRows()
    {
        var (user, _, _) = await SeedAsync(fixture);
        await using var db = fixture.CreateContext();

        var ex = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(
            "DELETE FROM users WHERE \"Id\" = {0}", user.Id));

        Assert.Equal(PostgresErrorCodes.RestrictViolation, ex.SqlState);
    }

    [Fact]
    public async Task AuditLog_IsAppendOnly()
    {
        var (user, _, _) = await SeedAsync(fixture);
        await using var db = fixture.CreateContext();
        var log = await db.AuditLogs.FirstAsync(a => a.EntityId == user.Id);
        db.AuditLogs.Remove(log);

        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task Schema_ContainsExpectedTablesAndEmailUniqueIndex()
    {
        await using var db = fixture.CreateContext();
        var connection = db.Database.GetDbConnection();
        await connection.OpenAsync();

        await using var tables = connection.CreateCommand();
        tables.CommandText = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'";
        var names = new List<string>();
        await using (var reader = await tables.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
            {
                names.Add(reader.GetString(0));
            }
        }

        Assert.Contains("users", names);
        Assert.Contains("applications", names);
        Assert.Contains("vulnerabilities", names);
        Assert.Contains("audit_logs", names);

        await using var indexes = connection.CreateCommand();
        indexes.CommandText = "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'ux_users_email'";
        var def = (string?)await indexes.ExecuteScalarAsync();
        Assert.Contains("UNIQUE", def, StringComparison.Ordinal);
    }
}


