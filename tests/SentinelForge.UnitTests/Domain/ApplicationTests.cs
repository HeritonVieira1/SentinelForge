using SentinelForge.Domain.Common;
using SentinelForge.Domain.Entities;
using DomainApplication = SentinelForge.Domain.Entities.Application;

namespace SentinelForge.UnitTests.Domain;

public sealed class ApplicationTests
{
    private static readonly DateTime Now = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Create_AcceptsHttpsRepositoryUrl()
    {
        var app = DomainApplication.Create("Portal", null, "https://github.com/org/repo", Guid.NewGuid(), Now);

        Assert.Equal("https://github.com/org/repo", app.RepositoryUrl);
        Assert.Equal(string.Empty, app.Description);
        Assert.True(app.IsActive);
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("ftp://host/repo")]
    [InlineData("não é url")]
    public void Create_RejectsNonHttpUrl(string url) =>
        Assert.Throws<DomainException>(() => DomainApplication.Create("Portal", null, url, Guid.NewGuid(), Now));

    [Fact]
    public void Create_RequiresOwner() =>
        Assert.Throws<DomainException>(() => DomainApplication.Create("Portal", null, null, Guid.Empty, Now));
}

