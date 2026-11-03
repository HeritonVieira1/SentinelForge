namespace SentinelForge.Application.Common;

internal static class InputValidation
{
    /// <summary>
    /// Verdadeiro se o texto contém caracteres de controle (exceto tab/LF/CR). Parâmetros de consulta com NUL (0x00)
    /// são rejeitados com 400 em vez de chegarem ao PostgreSQL, que os recusa e causaria um erro 500.
    /// </summary>
    public static bool HasControlCharacters(string? value) =>
        value is not null && value.Any(ch => char.IsControl(ch) && ch is not ('\t' or '\n' or '\r'));
}
