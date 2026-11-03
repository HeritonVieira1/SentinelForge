using SentinelForge.Domain.Common;
using SentinelForge.Domain.Enums;
using SentinelForge.Domain.ValueObjects;

namespace SentinelForge.UnitTests.Domain;

public sealed class CvssRatingTests
{
    public const string V40Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
    public const string V31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    // Faixas oficiais do CVSS: None 0.0; Low 0.1-3.9; Medium 4.0-6.9; High 7.0-8.9; Critical 9.0-10.0.
    [Theory]
    [InlineData("0.0", Severity.None)]
    [InlineData("0.1", Severity.Low)]
    [InlineData("3.9", Severity.Low)]
    [InlineData("4.0", Severity.Medium)]
    [InlineData("6.9", Severity.Medium)]
    [InlineData("7.0", Severity.High)]
    [InlineData("8.9", Severity.High)]
    [InlineData("9.0", Severity.Critical)]
    [InlineData("10.0", Severity.Critical)]
    public void Severity_IsDerivedFromScore_AtEveryBoundary(string score, Severity expected)
    {
        var rating = CvssRating.Create(decimal.Parse(score, System.Globalization.CultureInfo.InvariantCulture), CvssVersion.V40);

        Assert.Equal(expected, rating.Severity);
        Assert.Equal(expected, CvssRating.SeverityFor(rating.Score));
    }

    [Theory]
    [InlineData("-0.1")]
    [InlineData("10.1")]
    [InlineData("7.55")]
    [InlineData("100")]
    public void Create_RejectsInvalidScores(string score) =>
        Assert.Throws<DomainException>(() => CvssRating.Create(decimal.Parse(score, System.Globalization.CultureInfo.InvariantCulture), CvssVersion.V40));

    [Fact]
    public void Create_AcceptsValidV40AndV31Vectors()
    {
        Assert.Equal(V40Vector, CvssRating.Create(9.3m, CvssVersion.V40, V40Vector).Vector);
        Assert.Equal(V31Vector, CvssRating.Create(9.8m, CvssVersion.V31, V31Vector).Vector);
    }

    [Fact]
    public void Create_AcceptsV40VectorWithOptionalThreatAndEnvironmentalMetrics() =>
        Assert.NotNull(CvssRating.Create(7.5m, CvssVersion.V40, V40Vector + "/E:A/CR:H/MAV:N").Vector);

    [Theory]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")] // versão do vetor ≠ versão informada (4.0)
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N")] // falta SA
    [InlineData("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")] // valor inválido
    [InlineData("CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")] // métrica repetida
    [InlineData("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")] // sem prefixo
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/<script>")] // lixo
    public void Create_RejectsInvalidVectors(string vector) =>
        Assert.Throws<DomainException>(() => CvssRating.Create(9.3m, CvssVersion.V40, vector));

    [Fact]
    public void Create_RejectsOverlongVector() =>
        Assert.Throws<DomainException>(() => CvssRating.Create(9.3m, CvssVersion.V40, V40Vector + "/" + new string('A', 300)));

    [Theory]
    [InlineData("3.0", CvssVersion.V30)]
    [InlineData("3.1", CvssVersion.V31)]
    [InlineData("4.0", CvssVersion.V40)]
    public void ParseVersion_RoundTrips(string text, CvssVersion version)
    {
        Assert.Equal(version, CvssRating.ParseVersion(text));
        Assert.Equal(text, CvssRating.Format(version));
    }

    [Theory]
    [InlineData("2.0")]
    [InlineData("4")]
    [InlineData("")]
    public void ParseVersion_RejectsUnsupportedVersions(string text) =>
        Assert.Throws<DomainException>(() => CvssRating.ParseVersion(text));

    [Theory]
    [InlineData("cve-2024-3094", "CVE-2024-3094")]
    [InlineData(" CVE-2021-44228 ", "CVE-2021-44228")]
    public void CveIdentifier_Normalizes(string input, string expected)
    {
        Assert.True(CveIdentifier.TryNormalize(input, out var normalized));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("CVE-24-1")]
    [InlineData("CVE-2024-12")]
    [InlineData("../etc/passwd")]
    [InlineData("CVE-2024-1234?x=1")]
    [InlineData("")]
    public void CveIdentifier_RejectsInvalid(string input) => Assert.False(CveIdentifier.TryNormalize(input, out _));
}
