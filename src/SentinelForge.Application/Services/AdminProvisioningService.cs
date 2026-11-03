using SentinelForge.Application.Abstractions;
using SentinelForge.Application.Common;
using SentinelForge.Application.Contracts;
using SentinelForge.Application.Security;
using SentinelForge.Domain.Common;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Application.Services;

/// <summary>Provisiona o primeiro administrador. Só funciona enquanto não existir nenhum administrador.</summary>
public sealed class AdminProvisioningService(
    IUserRepository users,
    IUnitOfWork unitOfWork,
    IPasswordHasher hasher,
    TimeProvider time)
{
    public async Task<Result<UserDto>> ProvisionAsync(string? name, string? email, string? password, CancellationToken ct = default)
    {
        string normalizedEmail;
        try
        {
            normalizedEmail = User.NormalizeEmail(email ?? string.Empty);
        }
        catch (DomainException e)
        {
            return Result.Failure<UserDto>(ErrorKind.Validation, e.Message);
        }

        var passwordErrors = PasswordPolicy.Validate(password, normalizedEmail);
        if (passwordErrors.Count > 0)
        {
            return Result.Failure<UserDto>(ErrorKind.Validation, string.Join(' ', passwordErrors));
        }

        if (await users.AnyAdministratorAsync(ct))
        {
            return Result.Failure<UserDto>(ErrorKind.Conflict, "An administrator already exists.");
        }

        if (await users.FindByEmailAsync(normalizedEmail, ct) is not null)
        {
            return Result.Failure<UserDto>(ErrorKind.Conflict, "A user with this e-mail already exists.");
        }

        User admin;
        try
        {
            admin = User.Create(name ?? string.Empty, normalizedEmail, hasher.Hash(password!), UserRole.Administrator, time.GetUtcNow().UtcDateTime);
        }
        catch (DomainException e)
        {
            return Result.Failure<UserDto>(ErrorKind.Validation, e.Message);
        }

        users.Add(admin);
        await unitOfWork.SaveChangesAsync(ct);
        return Result.Success(admin.ToDto());
    }
}
