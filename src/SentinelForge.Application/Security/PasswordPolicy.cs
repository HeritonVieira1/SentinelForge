namespace SentinelForge.Application.Security;

/// <summary>Política de senha: 12–128 caracteres, com minúscula, maiúscula, dígito e símbolo.</summary>
public static class PasswordPolicy
{
    public const int MinLength = 12;
    public const int MaxLength = 128;

    private static readonly string[] Blocklist = ["password", "senha", "qwerty", "123456", "letmein", "admin"];

    public static IReadOnlyList<string> Validate(string? password, string? email = null)
    {
        var errors = new List<string>();

        if (string.IsNullOrEmpty(password))
        {
            errors.Add("Password is required.");
            return errors;
        }

        if (password.Length < MinLength)
        {
            errors.Add($"Password must have at least {MinLength} characters.");
        }

        if (password.Length > MaxLength)
        {
            errors.Add($"Password must have at most {MaxLength} characters.");
        }

        if (!password.Any(char.IsLower))
        {
            errors.Add("Password must contain a lowercase letter.");
        }

        if (!password.Any(char.IsUpper))
        {
            errors.Add("Password must contain an uppercase letter.");
        }

        if (!password.Any(char.IsDigit))
        {
            errors.Add("Password must contain a digit.");
        }

        if (!password.Any(c => !char.IsLetterOrDigit(c)))
        {
            errors.Add("Password must contain a symbol.");
        }

        if (Blocklist.Any(b => password.Contains(b, StringComparison.OrdinalIgnoreCase)))
        {
            errors.Add("Password is too common.");
        }

        var localPart = email?.Split('@')[0];
        if (localPart is { Length: >= 4 } && password.Contains(localPart, StringComparison.OrdinalIgnoreCase))
        {
            errors.Add("Password must not contain the e-mail name.");
        }

        return errors;
    }
}
