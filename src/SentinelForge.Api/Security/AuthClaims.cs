namespace SentinelForge.Api.Security;

internal static class AuthClaims
{
    public const string Subject = "sub";
    public const string Role = "role";
    public const string Session = "sid";
}

internal static class Policies
{
    public const string Administrator = nameof(Administrator);
}
