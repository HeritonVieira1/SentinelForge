using Microsoft.Extensions.Logging;
using SentinelForge.Application.Abstractions;
using SentinelForge.Application.Common;
using SentinelForge.Application.Contracts;
using SentinelForge.Application.Security;
using SentinelForge.Domain.Common;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Application.Services;

public sealed partial class AuthService(
    IUserRepository users,
    IRefreshTokenRepository refreshTokens,
    IAuditLogRepository audit,
    IUnitOfWork unitOfWork,
    IPasswordHasher hasher,
    ITokenService tokens,
    ICurrentUser current,
    TimeProvider time,
    AuthOptions options,
    ILogger<AuthService> logger)
{
    private const string InvalidCredentials = "Invalid credentials.";
    private const string InvalidRefreshToken = "Invalid or expired refresh token.";
    private const int MaxRefreshTokenLength = 256;

    /// <summary>Cadastra um usuário. O papel é sempre Developer: o cliente não escolhe o próprio perfil.</summary>
    public async Task<Result<UserDto>> RegisterAsync(RegisterRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            errors["name"] = ["Name is required."];
        }

        string? email = null;
        try
        {
            email = User.NormalizeEmail(request.Email ?? string.Empty);
        }
        catch (DomainException e)
        {
            errors["email"] = [e.Message];
        }

        var passwordErrors = PasswordPolicy.Validate(request.Password, email);
        if (passwordErrors.Count > 0)
        {
            errors["password"] = [.. passwordErrors];
        }

        if (errors.Count > 0)
        {
            return Result.Failure<UserDto>(new ResultError(ErrorKind.Validation, "One or more validation errors occurred.", errors));
        }

        if (await users.FindByEmailAsync(email!, ct) is not null)
        {
            return Result.Failure<UserDto>(ErrorKind.Conflict, "A user with this e-mail already exists.");
        }

        User user;
        try
        {
            user = User.Create(request.Name!, email!, hasher.Hash(request.Password!), UserRole.Developer, Now());
        }
        catch (DomainException e)
        {
            return Result.Failure<UserDto>(ErrorKind.Validation, e.Message);
        }

        users.Add(user);
        try
        {
            await unitOfWork.SaveChangesAsync(ct);
        }
        catch (ConflictException)
        {
            return Result.Failure<UserDto>(ErrorKind.Conflict, "A user with this e-mail already exists.");
        }

        return Result.Success(user.ToDto());
    }

    public async Task<Result<AuthTokens>> LoginAsync(LoginRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var now = Now();

        User? user = null;
        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            try
            {
                user = await users.FindByEmailAsync(User.NormalizeEmail(request.Email), ct);
            }
            catch (DomainException)
            {
                // E-mail malformado: trata como conta inexistente.
            }
        }

        // Sempre calcula um hash (real ou descartável) para não revelar, pelo tempo, se a conta existe.
        var verification = hasher.Verify(user?.PasswordHash ?? hasher.DummyHash, request.Password ?? string.Empty);

        if (user is null)
        {
            LogUnknownAccount(current.IpAddress);
            return Result.Failure<AuthTokens>(ErrorKind.Unauthorized, InvalidCredentials);
        }

        var locked = user.IsLockedOut(now);
        if (verification == PasswordVerification.Failed || locked || !user.IsActive)
        {
            if (!locked)
            {
                user.RegisterFailedLogin(now, options.MaxFailedLoginAttempts, TimeSpan.FromMinutes(options.LockoutMinutes));
            }

            audit.Add(NewAudit(user.Id, AuditAction.LoginFailed, now));
            await unitOfWork.SaveChangesAsync(ct);
            LogLoginFailed(user.Id, current.IpAddress, locked);
            return Result.Failure<AuthTokens>(ErrorKind.Unauthorized, InvalidCredentials);
        }

        user.RegisterSuccessfulLogin();
        if (verification == PasswordVerification.SuccessRehashNeeded)
        {
            user.ChangePasswordHash(hasher.Hash(request.Password!), now);
        }

        var result = IssueTokens(user, Guid.CreateVersion7(), now);
        audit.Add(NewAudit(user.Id, AuditAction.LoginSucceeded, now));
        await unitOfWork.SaveChangesAsync(ct);
        LogLoginSucceeded(user.Id, current.IpAddress);
        return Result.Success(result);
    }

    /// <summary>Troca um refresh token válido por um novo par (rotação). Reutilização revoga a sessão.</summary>
    public async Task<Result<AuthTokens>> RefreshAsync(string? rawRefreshToken, CancellationToken ct = default)
    {
        var now = Now();
        if (!IsPlausible(rawRefreshToken))
        {
            return Result.Failure<AuthTokens>(ErrorKind.Unauthorized, InvalidRefreshToken);
        }

        var stored = await refreshTokens.FindByHashAsync(tokens.HashRefreshToken(rawRefreshToken!), ct);
        if (stored is null || stored.RevokedAt is not null)
        {
            return Result.Failure<AuthTokens>(ErrorKind.Unauthorized, InvalidRefreshToken);
        }

        if (stored.UsedAt is not null)
        {
            return await HandleReuseAsync(stored, now, ct);
        }

        if (stored.IsExpired(now))
        {
            return Result.Failure<AuthTokens>(ErrorKind.Unauthorized, InvalidRefreshToken);
        }

        if (!await refreshTokens.TryConsumeAsync(stored.Id, now, ct))
        {
            // Outra requisição consumiu o token entre a leitura e a escrita: tratado como reutilização.
            return await HandleReuseAsync(stored, now, ct);
        }

        var user = await users.FindByIdAsync(stored.UserId, ct);
        if (user is null || !user.IsActive)
        {
            await refreshTokens.RevokeSessionAsync(stored.SessionId, "user inactive", now, ct);
            return Result.Failure<AuthTokens>(ErrorKind.Unauthorized, InvalidRefreshToken);
        }

        var result = IssueTokens(user, stored.SessionId, now);
        await unitOfWork.SaveChangesAsync(ct);
        return Result.Success(result);
    }

    /// <summary>Encerra a sessão associada ao refresh token. Idempotente: nunca revela se o token existia.</summary>
    public async Task LogoutAsync(string? rawRefreshToken, CancellationToken ct = default)
    {
        if (!IsPlausible(rawRefreshToken))
        {
            return;
        }

        var now = Now();
        var stored = await refreshTokens.FindByHashAsync(tokens.HashRefreshToken(rawRefreshToken!), ct);
        if (stored is null)
        {
            return;
        }

        await refreshTokens.RevokeSessionAsync(stored.SessionId, "logout", now, ct);
        audit.Add(NewAudit(stored.UserId, AuditAction.LoggedOut, now));
        await unitOfWork.SaveChangesAsync(ct);
    }

    private static bool IsPlausible(string? token) =>
        !string.IsNullOrWhiteSpace(token) && token.Length <= MaxRefreshTokenLength;

    private DateTime Now() => time.GetUtcNow().UtcDateTime;

    private AuditLog NewAudit(Guid userId, AuditAction action, DateTime now) =>
        AuditLog.Create(userId, action, nameof(User), userId, null, null, current.IpAddress, now);

    private AuthTokens IssueTokens(User user, Guid sessionId, DateTime now)
    {
        var refresh = tokens.NewRefreshToken();
        var entity = RefreshToken.Create(
            user.Id, sessionId, refresh.Hash, now, TimeSpan.FromDays(options.RefreshTokenDays), current.IpAddress);
        refreshTokens.Add(entity);

        var access = tokens.CreateAccessToken(user.Id, user.Role, sessionId, now);
        return new AuthTokens(access.Value, access.ExpiresAt, refresh.Raw, entity.ExpiresAt);
    }

    private async Task<Result<AuthTokens>> HandleReuseAsync(RefreshToken stored, DateTime now, CancellationToken ct)
    {
        await refreshTokens.RevokeSessionAsync(stored.SessionId, "refresh token reuse detected", now, ct);
        audit.Add(NewAudit(stored.UserId, AuditAction.RefreshTokenReuseDetected, now));
        await unitOfWork.SaveChangesAsync(ct);
        LogReuseDetected(stored.UserId, stored.SessionId, current.IpAddress);
        return Result.Failure<AuthTokens>(ErrorKind.Unauthorized, InvalidRefreshToken);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Login succeeded for user {UserId} from {IpAddress}")]
    private partial void LogLoginSucceeded(Guid userId, string? ipAddress);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Login failed for user {UserId} from {IpAddress} (locked: {Locked})")]
    private partial void LogLoginFailed(Guid userId, string? ipAddress, bool locked);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Login failed for unknown account from {IpAddress}")]
    private partial void LogUnknownAccount(string? ipAddress);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Refresh token reuse detected for user {UserId}, session {SessionId} revoked (from {IpAddress})")]
    private partial void LogReuseDetected(Guid userId, Guid sessionId, string? ipAddress);
}

