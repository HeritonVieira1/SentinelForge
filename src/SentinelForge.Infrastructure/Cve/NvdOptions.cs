namespace SentinelForge.Infrastructure.Cve;

/// <summary>Configuração da integração com a API pública do NVD (seção "Nvd"). A chave de API é opcional e secreta.</summary>
public sealed class NvdOptions
{
    public const string SectionName = "Nvd";

    public string BaseUrl { get; set; } = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    /// <summary>Chave de API do NVD (Nvd__ApiKey). Eleva o limite oficial de 5 para 50 requisições a cada 30 s.</summary>
    public string? ApiKey { get; set; }

    public int TimeoutSeconds { get; set; } = 10;

    public int CacheMinutes { get; set; } = 60;

    public int NotFoundCacheMinutes { get; set; } = 10;

    /// <summary>Após uma falha da fonte, novas chamadas são recusadas por este período (disjuntor simples).</summary>
    public int UnavailableCooldownSeconds { get; set; } = 30;

    public bool HasApiKey => !string.IsNullOrWhiteSpace(ApiKey);

    public void Validate()
    {
        if (!Uri.TryCreate(BaseUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("Nvd:BaseUrl must be an absolute https URL.");
        }

        if (TimeoutSeconds is < 1 or > 60)
        {
            throw new InvalidOperationException("Nvd:TimeoutSeconds must be between 1 and 60.");
        }
    }
}
