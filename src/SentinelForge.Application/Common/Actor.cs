using SentinelForge.Application.Abstractions;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Application.Common;

internal readonly record struct Actor(Guid Id, UserRole Role)
{
    public bool IsAdministrator => Role == UserRole.Administrator;

    public static Actor? From(ICurrentUser current) =>
        current.UserId is { } id && current.Role is { } role ? new Actor(id, role) : null;
}

internal static class Paging
{
    public static (int Page, int PageSize) Normalize(int page, int pageSize) =>
        (Math.Max(page, 1), Math.Clamp(pageSize, 1, 100));
}
