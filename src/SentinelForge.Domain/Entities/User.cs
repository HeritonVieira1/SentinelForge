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

    private void Touch(DateTime utcNow) => UpdatedAt = Guard.Utc(utcNow, nameof(UpdatedAt));
}
