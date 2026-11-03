namespace SentinelForge.Domain.Enums;

/// <summary>Severidade qualitativa derivada do CVSS. <see cref="Unrated"/> = sem avaliação CVSS (nada é inventado).</summary>
public enum Severity
{
    Unrated = 0,
    None = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}
