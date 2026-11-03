namespace SentinelForge.Application.Abstractions;

public enum PasswordVerification
{
    Failed,
    Success,
    SuccessRehashNeeded,
}

public interface IPasswordHasher
{
    /// <summary>Hash válido de uma senha descartável, usado para igualar o tempo de resposta de contas inexistentes.</summary>
    string DummyHash { get; }

    string Hash(string password);

    PasswordVerification Verify(string hash, string password);
}
