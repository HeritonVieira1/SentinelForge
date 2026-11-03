using SentinelForge.Domain.Common;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;

namespace SentinelForge.UnitTests.Domain;

public sealed class LockoutAndRefreshTokenTests
{
    private static readonly DateTime Now = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    private static User NewUser() => User.Create("Ana", "ana@example.com", "hash", UserRole.Developer, Now);

    [Fact]
    public void FailedLogins_LockAccountAtThreshold_AndSuccessResets()
    {
        var user = NewUser();

        for (var i = 0; i < 4; i++)
        {
            user.RegisterFailedLogin(Now, 5, Window);
        }

        Assert.False(user.IsLockedOut(Now));

        user.RegisterFailedLogin(Now, 5, Window);

        Assert.True(user.IsLockedOut(Now));
        Assert.True(user.IsLockedOut(Now.AddMinutes(14)));
        Assert.False(user.IsLockedOut(Now.AddMinutes(15)));

        user.RegisterSuccessfulLogin();
        Assert.False(user.IsLockedOut(Now));
        Assert.Equal(0, user.FailedLoginCount);
    }

    [Fact]
    public void RefreshToken_Create_ComputesExpiry_AndIsActiveUntilExpired()
    {
        var token = RefreshToken.Create(Guid.NewGuid(), Guid.NewGuid(), new string('a', 64), Now, TimeSpan.FromDays(7), "203.0.113.1");

        Assert.Equal(Now.AddDays(7), token.ExpiresAt);
        Assert.True(token.IsActive(Now.AddDays(6)));
        Assert.False(token.IsActive(Now.AddDays(7)));
    }

    [Theory]
    [InlineData("curto")]
    [InlineData("")]
    public void RefreshToken_Create_RejectsMalformedHash(string hash) =>
        Assert.Throws<DomainException>(() =>
            RefreshToken.Create(Guid.NewGuid(), Guid.NewGuid(), hash, Now, TimeSpan.FromDays(1), null));

    [Fact]
    public void RefreshToken_Create_RejectsNonPositiveLifetime() =>
        Assert.Throws<DomainException>(() =>
            RefreshToken.Create(Guid.NewGuid(), Guid.NewGuid(), new string('a', 64), Now, TimeSpan.Zero, null));
}
