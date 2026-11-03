using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SentinelForge.Application.Abstractions;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;
using DomainApplication = SentinelForge.Domain.Entities.Application;

namespace SentinelForge.Infrastructure.Auditing;

/// <summary>
/// Gera registros de auditoria para User, Application e Vulnerability no mesmo SaveChanges
/// (mesma transação) e impede exclusões físicas dessas entidades e alterações no próprio AuditLog.
/// </summary>
internal sealed class AuditSaveChangesInterceptor(ICurrentUser currentUser, TimeProvider timeProvider) : SaveChangesInterceptor
{
    private const string Redacted = "[REDACTED]";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private static readonly HashSet<string> SensitiveProperties = new(StringComparer.Ordinal) { nameof(User.PasswordHash) };

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        ArgumentNullException.ThrowIfNull(eventData);
        Audit(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(eventData);
        Audit(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    private static bool IsAudited(object entity) => entity is User or DomainApplication or Vulnerability;

    private static Dictionary<string, object?> Snapshot(IEnumerable<PropertyEntry> properties, bool original) =>
        properties.ToDictionary(
            p => p.Metadata.Name,
            p => SensitiveProperties.Contains(p.Metadata.Name) ? Redacted : (original ? p.OriginalValue : p.CurrentValue));

    private void Audit(DbContext? context)
    {
        if (context is null)
        {
            return;
        }

        context.ChangeTracker.DetectChanges();
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var logs = new List<AuditLog>();

        foreach (var entry in context.ChangeTracker.Entries().ToList())
        {
            if (entry.Entity is AuditLog && entry.State is EntityState.Modified or EntityState.Deleted)
            {
                throw new InvalidOperationException("Audit logs are append-only.");
            }

            if (!IsAudited(entry.Entity))
            {
                continue;
            }

            switch (entry.State)
            {
                case EntityState.Deleted:
                    throw new InvalidOperationException(
                        $"Physical deletion of {entry.Metadata.ClrType.Name} is not allowed; deactivate it instead.");

                case EntityState.Added:
                    logs.Add(NewLog(entry, AuditAction.Created, null, Snapshot(entry.Properties, original: false), now));
                    break;

                case EntityState.Modified:
                    var changed = entry.Properties.Where(p => p.IsModified).ToList();
                    if (changed.Count > 0)
                    {
                        logs.Add(NewLog(
                            entry,
                            AuditAction.Updated,
                            Snapshot(changed, original: true),
                            Snapshot(changed, original: false),
                            now));
                    }

                    break;
            }
        }

        context.Set<AuditLog>().AddRange(logs);
    }

    private AuditLog NewLog(
        EntityEntry entry,
        AuditAction action,
        Dictionary<string, object?>? oldValues,
        Dictionary<string, object?> newValues,
        DateTime now) =>
        AuditLog.Create(
            currentUser.UserId,
            action,
            entry.Metadata.ClrType.Name,
            (Guid)entry.Property("Id").CurrentValue!,
            oldValues is null ? null : JsonSerializer.Serialize(oldValues, JsonOptions),
            JsonSerializer.Serialize(newValues, JsonOptions),
            currentUser.IpAddress,
            now);
}
