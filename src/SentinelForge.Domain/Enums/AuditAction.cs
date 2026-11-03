namespace SentinelForge.Domain.Enums;

public enum AuditAction
{
    Created = 1,
    Updated = 2,
    LoginSucceeded = 3,
    LoginFailed = 4,
    LoggedOut = 5,
    RefreshTokenReuseDetected = 6,
    SessionsRevoked = 7,
}
