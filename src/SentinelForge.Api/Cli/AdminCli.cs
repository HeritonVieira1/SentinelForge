using SentinelForge.Application.Common;
using SentinelForge.Application.Services;

namespace SentinelForge.Api.Cli;

/// <summary>
/// Comando administrativo: <c>dotnet run --project src/SentinelForge.Api -- provision-admin --email a@b.com --name "Nome"</c>.
/// A senha é lida apenas da variável de ambiente SENTINELFORGE_ADMIN_PASSWORD (nunca de argumentos nem de arquivos)
/// e nunca é escrita na saída ou nos logs. Só funciona enquanto não existir nenhum administrador.
/// </summary>
internal static class AdminCli
{
    public const string Command = "provision-admin";
    public const string PasswordVariable = "SENTINELFORGE_ADMIN_PASSWORD";

    public static async Task<int> RunAsync(IServiceProvider services, string[] args)
    {
        var email = Option(args, "--email");
        var name = Option(args, "--name");
        var password = Environment.GetEnvironmentVariable(PasswordVariable);

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(name) || string.IsNullOrEmpty(password))
        {
            await Console.Error.WriteLineAsync(
                $"Usage: {Command} --email <email> --name <name>  (password via the {PasswordVariable} environment variable)");
            return 64;
        }

        await using var scope = services.CreateAsyncScope();
        var result = await scope.ServiceProvider.GetRequiredService<AdminProvisioningService>().ProvisionAsync(name, email, password);

        if (result.IsSuccess)
        {
            await Console.Out.WriteLineAsync($"Administrator created: {result.Value!.Id} ({result.Value.Email})");
            return 0;
        }

        await Console.Error.WriteLineAsync($"Could not provision administrator: {result.Error!.Message}");
        return result.Error.Kind == ErrorKind.Conflict ? 2 : 1;
    }

    private static string? Option(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}
