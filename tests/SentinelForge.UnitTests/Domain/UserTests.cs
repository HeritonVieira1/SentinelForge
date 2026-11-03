using SentinelForge.Domain.Common;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;

namespace SentinelForge.UnitTests.Domain;

public sealed class UserTests
{
    private static readonly DateTime Now = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Create_NormalizesEmailAndStartsActive()
    {
        var user = User.Create("  Ana ", "Ana@Example.COM", "hash", UserRole.SecurityAnalyst, Now);

        Assert.Equal("Ana", user.Name);
        Assert.Equal("ana@example.com", user.Email);
        Assert.True(user.IsActive);
        Assert.Equal(Now, user.CreatedAt);
        Assert.NotEqual(Guid.Empty, user.Id);
    }

    [Theory]
    [InlineData("")]
    [InlineData("sem-arroba")]
    [InlineData("a@b")]
    [InlineData("a b@c.com")]
    public void Create_RejectsInvalidEmail(string email) =>
        Assert.Throws<DomainException>(() => User.Create("Ana", email, "hash", UserRole.Developer, Now));

    [Fact]
    public void Create_RejectsUndefinedRole() =>
        Assert.Throws<DomainException>(() => User.Create("Ana", "a@b.com", "hash", (UserRole)99, Now));

    [Fact]
    public void Create_RejectsEmptyPasswordHash() =>
        Assert.Throws<DomainException>(() => User.Create("Ana", "a@b.com", " ", UserRole.Developer, Now));

    [Fact]
    public void Create_RejectsNonUtcDate() =>
        Assert.Throws<DomainException>(() =>
            User.Create("Ana", "a@b.com", "hash", UserRole.Developer, new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Local)));
}

