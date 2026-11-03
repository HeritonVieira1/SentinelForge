using SentinelForge.Domain.Common;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Domain.Entities;

public sealed class User
{
    public const int NameMaxLength = 150;
    public const int EmailMaxLength = 254;
    public const int PasswordHashMaxLength = 512;

    private User()
    {
    }

    public Guid Id { get; private set; }

    public string Name { get; private set; } = string.Empty;

    /// <summary>E-mail normalizado em minúsculas.</summary>
    public string Email { get; private set; } = string.Empty;

    /// <summary>Hash da senha (nunca a senha em texto puro). O algoritmo de hash será definido na Fase 3.</summary>
    public string PasswordHash { get; private set; } = string.Empty;

    public UserRole Role { get; private set; }

    public bool IsActive { get; private set; }

    public DateTime CreatedAt { get; private set; }

    public DateTime UpdatedAt { get; private set; }

    /// <summary>Falhas de login consecutivas desde o último sucesso.</summary>
    public int FailedLoginCount { get; private set; }

    /// <summary>Fim do bloqueio temporário da conta, quando houver.</summary>
    public DateTime? LockoutEnd { get; private set; }

    /// <summary>Normaliza (trim + minúsculas) e valida um e-mail; lança <see cref="DomainException"/> se inválido.</summary>
    public static string NormalizeEmail(string email) => Guard.Email(email);

    public static User Create(string name, string email, string passwordHash, UserRole role, DateTime utcNow) => new()
    {
        Id = Guid.CreateVersion7(),
        Name = Guard.NotBlank(name, nameof(Name), NameMaxLength),
        Email = Guard.Email(email),
        PasswordHash = Guard.NotBlank(passwordHash, nameof(PasswordHash), PasswordHashMaxLength),
        Role = Guard.Defined(role, nameof(Role)),
        IsActive = true,
        CreatedAt = Guard.Utc(utcNow, nameof(CreatedAt)),
        UpdatedAt = utcNow,
    };

    public void ChangeRole(UserRole role, DateTime utcNow)
    {
        Role = Guard.Defined(role, nameof(Role));
        Touch(utcNow);
    }

    public void ChangePasswordHash(string passwordHash, DateTime utcNow)
    {
        PasswordHash = Guard.NotBlank(passwordHash, nameof(PasswordHash), PasswordHashMaxLength);
        Touch(utcNow);
    }

    public void Deactivate(DateTime utcNow)
    {
        IsActive = false;
        Touch(utcNow);
    }

    public void Activate(DateTime utcNow)
    {
        IsActive = true;
        Touch(utcNow);
    }

    public bool IsLockedOut(DateTime utcNow) => LockoutEnd is { } end && end > utcNow;

    /// <summary>Registra uma falha de login e bloqueia a conta ao atingir o limite.</summary>
    public void RegisterFailedLogin(DateTime utcNow, int maxAttempts, TimeSpan lockoutDuration)
    {
        Guard.Utc(utcNow, nameof(utcNow));
        FailedLoginCount++;

        if (FailedLoginCount >= maxAttempts)
        {
            LockoutEnd = utcNow.Add(lockoutDuration);
            FailedLoginCount = 0;
        }
    }

    public void RegisterSuccessfulLogin()
    {
        FailedLoginCount = 0;
        LockoutEnd = null;
    }

    private void Touch(DateTime utcNow) => UpdatedAt = Guard.Utc(utcNow, nameof(UpdatedAt));
}


