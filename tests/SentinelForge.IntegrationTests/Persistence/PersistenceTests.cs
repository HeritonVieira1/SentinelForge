using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;
using SentinelForge.Domain.ValueObjects;
using DomainApplication = SentinelForge.Domain.Entities.Application;

namespace SentinelForge.IntegrationTests.Persistence;

[Collection(PostgresTestGroup.Name)]
public sealed class PersistenceTests(PostgresFixture fixture)
{
    private const string FakeHash = "hash-opaco-de-teste";

    private static User NewUser(string? email = null) =>
        User.Create("Ana Teste", email ?? $"{Guid.NewGuid():N}@example.com", FakeHash, UserRole.SecurityAnalyst, DateTime.UtcNow);

    private static DomainApplication NewApp(Guid ownerId) =>
        DomainApplication.Create("Portal", "desc", "https://github.com/org/repo", ownerId, DateTime.UtcNow);

    private static Vulnerability NewVuln(Guid appId, Guid createdBy, Guid? assignee = null) =>
        Vulnerability.Create(
            "SQL Injection", "desc", "Injection", "CVE-2024-12345", "Parametrizar",
            CvssRating.Create(7.5m, CvssVersion.V40, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
            DateTime.UtcNow.AddDays(-1), appId, assignee, createdBy, DateTime.UtcNow);

    private static async Task<(User User, DomainApplication App, Vulnerability Vuln)> SeedAsync(PostgresFixture f)
    {
        await using var db = f.CreateContext();
        var user = NewUser();
        db.Users.Add(user);
        await db.SaveChangesAsync();
        var app = NewApp(user.Id);
        db.Applications.Add(app);
        await db.SaveChangesAsync();
        var vuln = NewVuln(app.Id, user.Id, user.Id);
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
        Assert.Equal(UserRole.SecurityAnalyst, loaded.Role);
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
        Assert.Equal(7.5m, loaded.CvssScore);
        Assert.Equal(CvssVersion.V40, loaded.CvssVersion);
        Assert.StartsWith("CVSS:4.0/", loaded.CvssVector, StringComparison.Ordinal);
        Assert.Equal(VulnerabilityStatus.New, loaded.Status);
        Assert.Equal(user.Id, loaded.CreatedByUserId);
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
    public async Task ResolvingAndVerifying_PersistsDates_AndHistory()
    {
        var (user, _, vuln) = await SeedAsync(fixture);
        await using (var db = fixture.CreateContext())
        {
            var tracked = await db.Vulnerabilities.SingleAsync(v => v.Id == vuln.Id);
            tracked.ChangeStatus(VulnerabilityStatus.Triaged, user.Id, DateTime.UtcNow);
            tracked.ChangeStatus(VulnerabilityStatus.InProgress, user.Id, DateTime.UtcNow);
            tracked.ChangeStatus(VulnerabilityStatus.Resolved, user.Id, DateTime.UtcNow);
            tracked.ChangeStatus(VulnerabilityStatus.Verified, user.Id, DateTime.UtcNow);
            await db.SaveChangesAsync();
        }

        await using var read = fixture.CreateContext();
        var loaded = await read.Vulnerabilities.AsNoTracking().SingleAsync(v => v.Id == vuln.Id);
        Assert.Equal(VulnerabilityStatus.Verified, loaded.Status);
        Assert.NotNull(loaded.ResolvedAt);
        Assert.NotNull(loaded.VerifiedAt);
        Assert.Equal(user.Id, loaded.ResolvedByUserId);

        var history = await read.VulnerabilityHistory.AsNoTracking().Where(h => h.VulnerabilityId == vuln.Id).ToListAsync();
        Assert.Equal(1, history.Count(h => h.ChangeType == VulnerabilityChangeType.Created));
        Assert.Equal(3, history.Count(h => h.ChangeType == VulnerabilityChangeType.StatusChanged));
        Assert.Single(history, h => h.ChangeType == VulnerabilityChangeType.FixVerified);
    }

    [Fact]
    public async Task Database_RejectsSeverityThatDivergesFromScore()
    {
        var (_, _, vuln) = await SeedAsync(fixture);
        await using var db = fixture.CreateContext();

        // A pontuação 9.5 exige 'Critical'; a linha ainda diz 'High'.
        var ex = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(
            "UPDATE vulnerabilities SET \"CvssScore\" = 9.5 WHERE \"Id\" = {0}", vuln.Id));

        Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
        Assert.Contains("severity_matches_score", ex.ConstraintName, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Database_RejectsScoreOutOfRange_AndVectorWithoutScore()
    {
        var (_, _, vuln) = await SeedAsync(fixture);
        await using var db = fixture.CreateContext();

        var outOfRange = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(
            "UPDATE vulnerabilities SET \"CvssScore\" = 11, \"Severity\" = 'Critical' WHERE \"Id\" = {0}", vuln.Id));
        var vectorWithoutScore = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(
            "UPDATE vulnerabilities SET \"CvssScore\" = NULL, \"CvssVersion\" = NULL, \"Severity\" = 'Unrated' WHERE \"Id\" = {0}", vuln.Id));

        Assert.Equal(PostgresErrorCodes.CheckViolation, outOfRange.SqlState);
        Assert.Equal(PostgresErrorCodes.CheckViolation, vectorWithoutScore.SqlState);
    }

    [Fact]
    public async Task History_IsAppendOnly_EvenWithDirectDatabaseAccess()
    {
        var (_, _, vuln) = await SeedAsync(fixture);
        await using var db = fixture.CreateContext();

        var update = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(
            "UPDATE vulnerability_history SET \"NewValue\" = 'adulterado' WHERE \"VulnerabilityId\" = {0}", vuln.Id));
        var delete = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync(
            "DELETE FROM vulnerability_history WHERE \"VulnerabilityId\" = {0}", vuln.Id));
        var truncate = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync("TRUNCATE vulnerability_history"));

        Assert.All(new[] { update, delete, truncate }, e => Assert.Equal("42501", e.SqlState));
    }

    [Fact]
    public async Task History_CannotBeModifiedOrDeleted_ThroughTheApplication()
    {
        var (_, _, vuln) = await SeedAsync(fixture);
        await using var db = fixture.CreateContext();
        var entry = await db.VulnerabilityHistory.FirstAsync(h => h.VulnerabilityId == vuln.Id);
        db.VulnerabilityHistory.Remove(entry);

        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task ConcurrentUpdates_AreDetected_InsteadOfOverwritingSilently()
    {
        var (user, _, vuln) = await SeedAsync(fixture);
        await using var first = fixture.CreateContext();
        await using var second = fixture.CreateContext();
        var a = await first.Vulnerabilities.SingleAsync(v => v.Id == vuln.Id);
        var b = await second.Vulnerabilities.SingleAsync(v => v.Id == vuln.Id);

        a.ChangeStatus(VulnerabilityStatus.Triaged, user.Id, DateTime.UtcNow);
        await first.SaveChangesAsync();
        b.ChangeStatus(VulnerabilityStatus.AcceptedRisk, user.Id, DateTime.UtcNow, "justificativa");

        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => second.SaveChangesAsync());
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
        var (user, _, vuln) = await SeedAsync(fixture);
        await using (var db = fixture.CreateContext())
        {
            var tracked = await db.Vulnerabilities.SingleAsync(v => v.Id == vuln.Id);
            tracked.Update(tracked.Title, tracked.Description, tracked.Category, tracked.CveId, tracked.Remediation,
                CvssRating.Create(9.8m, CvssVersion.V40, tracked.CvssVector), user.Id, DateTime.UtcNow);
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










