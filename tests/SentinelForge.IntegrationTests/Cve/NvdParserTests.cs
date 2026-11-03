using System.Text.Json;
using SentinelForge.Application.Abstractions;
using SentinelForge.Domain.ValueObjects;
using SentinelForge.Infrastructure.Cve;

namespace SentinelForge.IntegrationTests.Cve;

/// <summary>Parser do NVD exercitado contra respostas REAIS da API 2.0 (fixtures capturadas sem edição).</summary>
public sealed class NvdParserTests
{
    private static readonly DateTime Now = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    private static CveInfo ParseFound(string fixture, string cveId)
    {
        var result = NvdResponseParser.Parse(Fixtures.Read(fixture), cveId, Now);
        Assert.Equal(CveLookupStatus.Found, result.Status);
        return result.Info!;
    }

    [Fact]
    public void RealResponse_WithCvss31And40_PrefersV40_AndPreservesTheSource()
    {
        var info = ParseFound("nvd-CVE-2024-53677.json", "CVE-2024-53677");

        Assert.Equal("CVE-2024-53677", info.CveId);
        Assert.Equal("NVD", info.Source);
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2024-53677", info.SourceUrl);
        Assert.Equal(Now, info.RetrievedAt);
        Assert.False(string.IsNullOrWhiteSpace(info.Description));
        Assert.NotNull(info.PublishedAt);
        Assert.NotNull(info.LastModifiedAt);
        Assert.Equal(DateTimeKind.Utc, info.PublishedAt!.Value.Kind);

        Assert.Contains(info.Metrics, m => m.Version == "3.1");
        Assert.Contains(info.Metrics, m => m.Version == "4.0");
        Assert.Equal("4.0", info.PreferredMetric!.Version);
        Assert.StartsWith("CVSS:4.0/", info.PreferredMetric.Vector, StringComparison.Ordinal);
    }

    [Fact]
    public void RealResponse_WithOnlyCvss31_UsesIt()
    {
        var info = ParseFound("nvd-CVE-2024-3094.json", "CVE-2024-3094");

        Assert.All(info.Metrics, m => Assert.Equal("3.1", m.Version));
        Assert.Equal("3.1", info.PreferredMetric!.Version);
        Assert.Equal(10.0m, info.PreferredMetric.Score);
        Assert.Equal("Critical", info.PreferredMetric.Severity);
    }

    [Theory]
    [InlineData("nvd-CVE-2024-53677.json", "CVE-2024-53677")]
    [InlineData("nvd-CVE-2024-3094.json", "CVE-2024-3094")]
    public void Severity_ComputedByTheOfficialRanges_MatchesWhatTheNvdReports(string fixture, string cveId)
    {
        var info = ParseFound(fixture, cveId);

        // Confere cada métrica com o baseSeverity que o próprio NVD informa (verdade de referência).
        using var raw = JsonDocument.Parse(Fixtures.Read(fixture));
        var reported = raw.RootElement.GetProperty("vulnerabilities")[0].GetProperty("cve").GetProperty("metrics")
            .EnumerateObject().Where(p => p.Name.StartsWith("cvssMetricV3", StringComparison.Ordinal) || p.Name == "cvssMetricV40")
            .SelectMany(p => p.Value.EnumerateArray())
            .Select(e => (Score: e.GetProperty("cvssData").GetProperty("baseScore").GetDecimal(),
                          Severity: e.GetProperty("cvssData").GetProperty("baseSeverity").GetString()!))
            .ToList();

        Assert.NotEmpty(info.Metrics);
        Assert.Equal(reported.Count, info.Metrics.Count);
        foreach (var metric in info.Metrics)
        {
            var nvd = reported.First(r => r.Score == metric.Score);
            Assert.Equal(nvd.Severity, metric.Severity, ignoreCase: true);
            Assert.Equal(CvssRating.SeverityFor(metric.Score).ToString(), metric.Severity);
        }
    }

    [Fact]
    public void RealResponse_References_AreOnlyAbsoluteHttpUrls_WithTheirSource()
    {
        var info = ParseFound("nvd-CVE-2024-3094.json", "CVE-2024-3094");

        using var raw = JsonDocument.Parse(Fixtures.Read("nvd-CVE-2024-3094.json"));
        var rawCount = raw.RootElement.GetProperty("vulnerabilities")[0].GetProperty("cve").GetProperty("references").GetArrayLength();

        Assert.NotEmpty(info.References);
        Assert.Equal(rawCount, info.References.Count);
        Assert.All(info.References, r =>
        {
            Assert.True(Uri.TryCreate(r.Url, UriKind.Absolute, out var uri));
            Assert.True(uri!.Scheme is "http" or "https");
        });
        Assert.Contains(info.References, r => !string.IsNullOrEmpty(r.Source));
    }

    [Fact]
    public void RealNotFoundResponse_IsReportedAsNotFound() =>
        Assert.Equal(CveLookupStatus.NotFound, NvdResponseParser.Parse(Fixtures.Read("nvd-not-found.json"), "CVE-2099-99999", Now).Status);

    [Fact]
    public void HostileExternalContent_IsSanitized()
    {
        // Entrada propositalmente hostil (não é uma resposta do NVD): o parser não pode confiar na fonte externa.
        const string Json = """
        {"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","descriptions":[{"lang":"es","value":"hola"},{"lang":"en","value":"english text"}],
         "metrics":{"cvssMetricV31":[
            {"source":"x","type":"Primary","cvssData":{"version":"3.1","baseScore":11.0,"vectorString":"v"}},
            {"source":"x","type":"Primary","cvssData":{"version":"3.1","baseScore":7.55,"vectorString":"v"}},
            {"source":"x","type":"Primary","cvssData":{"version":"2.0","baseScore":5.0,"vectorString":"v"}},
            {"source":"x","type":"Primary","cvssData":{"version":"3.1","baseScore":7.5,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}]},
         "references":[
            {"url":"javascript:alert(1)"},{"url":"data:text/html,<script>x</script>"},{"url":"file:///etc/passwd"},
            {"url":"ftp://host/x"},{"url":"/relative/path"},{"url":""},
            {"url":"https://example.org/advisory","source":"example","tags":["Patch"]},{"url":"http://example.org/other"}]}}]}
        """;

        var info = NvdResponseParser.Parse(Json, "CVE-2024-0001", Now).Info!;

        Assert.Equal("english text", info.Description);
        var metric = Assert.Single(info.Metrics);                  // notas fora da faixa/precisão e versões não suportadas são descartadas
        Assert.Equal(7.5m, metric.Score);
        Assert.Equal("High", metric.Severity);
        Assert.Equal(["https://example.org/advisory", "http://example.org/other"], info.References.Select(r => r.Url));
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("{}")]
    [InlineData("""{"vulnerabilities":"nope"}""")]
    [InlineData("""{"vulnerabilities":[{"cve":{"id":"CVE-2000-0001"}}]}""")] // CVE diferente do solicitado
    public void UnexpectedShape_ThrowsJsonException(string body) =>
        Assert.ThrowsAny<JsonException>(() => NvdResponseParser.Parse(body, "CVE-2024-0001", Now));
}

