using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using SentinelForge.Api.Cli;
using SentinelForge.Domain.Enums;
using SentinelForge.IntegrationTests.Persistence;

namespace SentinelForge.IntegrationTests.Security;

/// <summary>Usa um banco vazio próprio: o provisionamento só funciona enquanto não existe administrador.</summary>
[Collection(PostgresTestGroup.Name)]
public sealed class AdminProvisioningTests(PostgresFixture db)
{
    private static async Task<(int Code, string Out, string Err)> RunCliAsync(IServiceProvider services, string? password, params string[] args)
    {
        var previousOut = Console.Out;
        var previousErr = Console.Error;
        var previousPassword = Environment.GetEnvironmentVariable(AdminCli.PasswordVariable);
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        Console.SetOut(stdout);
        Console.SetError(stderr);
        Environment.SetEnvironmentVariable(AdminCli.PasswordVariable, password);
        try
        {
            var code = await AdminCli.RunAsync(services, [AdminCli.Command, .. args]);
            return (code, stdout.ToString(), stderr.ToString());
        }
        finally
        {
            Console.SetOut(previousOut);
            Console.SetError(previousErr);
            Environment.SetEnvironmentVariable(AdminCli.PasswordVariable, previousPassword);
        }
    }

    [Fact]
    public async Task ProvisionAdmin_CreatesFirstAdministrator_WithoutExposingPassword_AndOnlyOnce()
    {
        using var factory = new ApiFactory(await db.CreateExtraDatabaseAsync(), db.JwtKey);
        const string Password = "Pr0visioned!Secret#99";

        var weak = await RunCliAsync(factory.Services, "fraca", "--email", "root@example.com", "--name", "Root");
        var missing = await RunCliAsync(factory.Services, null, "--email", "root@example.com", "--name", "Root");
        var first = await RunCliAsync(factory.Services, Password, "--email", "root@example.com", "--name", "Root");
        var second = await RunCliAsync(factory.Services, Password, "--email", "outro@example.com", "--name", "Outro");

        Assert.Equal(1, weak.Code);
        Assert.Equal(64, missing.Code);
        Assert.Equal(0, first.Code);
        Assert.Equal(2, second.Code); // já existe administrador
        foreach (var output in new[] { weak, missing, first, second })
        {
            Assert.DoesNotContain(Password, output.Out + output.Err, StringComparison.Ordinal);
        }

        // O administrador provisionado consegue autenticar e recebe o papel correto.
        using var client = factory.CreateClient();
        using var login = await client.PostAsJsonAsync("/api/auth/login", new { email = "root@example.com", password = Password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var token = (await login.Content.ReadFromJsonAsync<TokenView>(ApiContext.Json))!;
        Assert.Equal("Administrator", new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().ReadJsonWebToken(token.AccessToken).GetClaim("role").Value);
    }

    [Fact]
    public async Task ProvisionAdmin_PersistsOnlyAPasswordHash()
    {
        var connection = await db.CreateExtraDatabaseAsync();
        using var factory = new ApiFactory(connection, db.JwtKey);
        const string Password = "An0ther!Secret#2026";

        var result = await RunCliAsync(factory.Services, Password, "--email", "admin2@example.com", "--name", "Admin 2");

        Assert.Equal(0, result.Code);
        await using var read = db.CreateContext(connectionString: connection);
        var admin = await read.Users.AsNoTracking().SingleAsync(u => u.Email == "admin2@example.com");
        Assert.Equal(UserRole.Administrator, admin.Role);
        Assert.NotEqual(Password, admin.PasswordHash);
    }
}
