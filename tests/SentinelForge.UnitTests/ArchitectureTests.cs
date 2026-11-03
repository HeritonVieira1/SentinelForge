using System.Reflection;
using SentinelForge.Application;
using SentinelForge.Domain;
using SentinelForge.Infrastructure;

namespace SentinelForge.UnitTests;

/// <summary>Garante a regra de dependência da Clean Architecture.</summary>
public sealed class ArchitectureTests
{
    private static string[] References(Assembly assembly) =>
        [.. assembly.GetReferencedAssemblies().Select(a => a.Name!)];

    [Fact]
    public void Domain_DoesNotDependOnOtherLayers()
    {
        var refs = References(typeof(DomainAssemblyMarker).Assembly);

        Assert.DoesNotContain(refs, r => r.StartsWith("SentinelForge.", StringComparison.Ordinal));
    }

    [Fact]
    public void Application_DependsOnlyOnDomain()
    {
        var refs = References(typeof(ApplicationAssemblyMarker).Assembly)
            .Where(r => r.StartsWith("SentinelForge.", StringComparison.Ordinal));

        Assert.All(refs, r => Assert.Equal("SentinelForge.Domain", r));
    }

    [Fact]
    public void Infrastructure_DoesNotDependOnApi()
    {
        var refs = References(typeof(DependencyInjection).Assembly);

        Assert.DoesNotContain("SentinelForge.Api", refs);
    }
}
