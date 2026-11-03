using SentinelForge.Application.Abstractions;
using SentinelForge.Application.Common;
using SentinelForge.Application.Contracts;
using SentinelForge.Domain.Common;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Application.Services;

public sealed class UserService(
    IUserRepository users,
    IRefreshTokenRepository refreshTokens,
    IAuditLogRepository audit,
    IUnitOfWork unitOfWork,
    ICurrentUser current,
    TimeProvider time)
{
    public async Task<Result<PagedResult<UserDto>>> ListAsync(int page, int pageSize, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { IsAdministrator: true })
        {
            return Result.Failure<PagedResult<UserDto>>(ErrorKind.Forbidden, "Access denied.");
        }

        var (p, size) = Paging.Normalize(page, pageSize);
        var result = await users.ListAsync(p, size, ct);
        return Result.Success(new PagedResult<UserDto>([.. result.Items.Select(u => u.ToDto())], result.Page, result.PageSize, result.TotalCount));
    }

    /// <summary>Administradores veem qualquer usuário; os demais, apenas a si mesmos (outros ids retornam 404).</summary>
    public async Task<Result<UserDto>> GetAsync(Guid id, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<UserDto>(ErrorKind.Unauthorized, "Authentication required.");
        }

        if (!actor.IsAdministrator && actor.Id != id)
        {
            return Result.Failure<UserDto>(ErrorKind.NotFound, "User not found.");
        }

        var user = await users.FindByIdAsync(id, ct);
        return user is null
            ? Result.Failure<UserDto>(ErrorKind.NotFound, "User not found.")
            : Result.Success(user.ToDto());
    }

    public async Task<Result<UserDto>> ChangeRoleAsync(Guid id, UserRole role, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { IsAdministrator: true } actor)
        {
            return Result.Failure<UserDto>(ErrorKind.Forbidden, "Access denied.");
        }

        if (actor.Id == id)
        {
            return Result.Failure<UserDto>(ErrorKind.Forbidden, "You cannot change your own role.");
        }

        if (!Enum.IsDefined(role))
        {
            return Result.Failure<UserDto>(ErrorKind.Validation, "Role is invalid.");
        }

        var user = await users.FindByIdAsync(id, ct);
        if (user is null)
        {
            return Result.Failure<UserDto>(ErrorKind.NotFound, "User not found.");
        }

        if (user.Role != role)
        {
            var now = time.GetUtcNow().UtcDateTime;
            user.ChangeRole(role, now);

            // O papel muda o que o usuário pode fazer: sessões existentes precisam ser reautenticadas.
            await refreshTokens.RevokeAllForUserAsync(user.Id, "role changed", now, ct);
            audit.Add(AuditLog.Create(actor.Id, AuditAction.SessionsRevoked, nameof(User), user.Id, null, null, current.IpAddress, now));
            await unitOfWork.SaveChangesAsync(ct);
        }

        return Result.Success(user.ToDto());
    }

    public async Task<Result> RevokeSessionsAsync(Guid id, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { IsAdministrator: true } actor)
        {
            return Result.Failure(ErrorKind.Forbidden, "Access denied.");
        }

        if (await users.FindByIdAsync(id, ct) is null)
        {
            return Result.Failure(ErrorKind.NotFound, "User not found.");
        }

        var now = time.GetUtcNow().UtcDateTime;
        await refreshTokens.RevokeAllForUserAsync(id, "revoked by administrator", now, ct);
        audit.Add(AuditLog.Create(actor.Id, AuditAction.SessionsRevoked, nameof(User), id, null, null, current.IpAddress, now));
        await unitOfWork.SaveChangesAsync(ct);
        return Result.Success();
    }
}
