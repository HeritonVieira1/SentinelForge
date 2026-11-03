using SentinelForge.Domain.Common;

namespace SentinelForge.Domain.Entities;

public sealed class Application
{
    public const int NameMaxLength = 150;
    public const int DescriptionMaxLength = 2000;
    public const int RepositoryUrlMaxLength = 500;

    private readonly List<Vulnerability> _vulnerabilities = [];

    private Application()
    {
    }

    public Guid Id { get; private set; }

    public string Name { get; private set; } = string.Empty;

    public string Description { get; private set; } = string.Empty;

    public string? RepositoryUrl { get; private set; }

    public bool IsActive { get; private set; }

    public DateTime CreatedAt { get; private set; }

    public DateTime UpdatedAt { get; private set; }

    public Guid OwnerUserId { get; private set; }

    public User? Owner { get; private set; }

    public IReadOnlyCollection<Vulnerability> Vulnerabilities => _vulnerabilities;

    public static Application Create(
        string name,
        string? description,
        string? repositoryUrl,
        Guid ownerUserId,
        DateTime utcNow) => new()
    {
        Id = Guid.CreateVersion7(),
        Name = Guard.NotBlank(name, nameof(Name), NameMaxLength),
        Description = Guard.MaxLength(description, nameof(Description), DescriptionMaxLength),
        RepositoryUrl = Guard.HttpUrl(repositoryUrl, nameof(RepositoryUrl), RepositoryUrlMaxLength),
        OwnerUserId = Guard.NotEmpty(ownerUserId, nameof(OwnerUserId)),
        IsActive = true,
        CreatedAt = Guard.Utc(utcNow, nameof(CreatedAt)),
        UpdatedAt = utcNow,
    };

    public void Update(string name, string? description, string? repositoryUrl, DateTime utcNow)
    {
        Name = Guard.NotBlank(name, nameof(Name), NameMaxLength);
        Description = Guard.MaxLength(description, nameof(Description), DescriptionMaxLength);
        RepositoryUrl = Guard.HttpUrl(repositoryUrl, nameof(RepositoryUrl), RepositoryUrlMaxLength);
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
