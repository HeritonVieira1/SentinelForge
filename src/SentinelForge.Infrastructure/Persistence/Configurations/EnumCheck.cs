namespace SentinelForge.Infrastructure.Persistence.Configurations;

/// <summary>Gera restrições CHECK a partir dos nomes do enum, garantindo que o banco rejeite valores inválidos.</summary>
internal static class EnumCheck
{
    public const int ColumnLength = 32;

    public static string In<TEnum>(string column)
        where TEnum : struct, Enum
    {
        var values = string.Join(", ", Enum.GetNames<TEnum>().Select(n => $"'{n}'"));
        return $"\"{column}\" IN ({values})";
    }
}
