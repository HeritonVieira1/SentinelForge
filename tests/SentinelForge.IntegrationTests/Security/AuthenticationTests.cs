using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using SentinelForge.Domain.Enums;
using SentinelForge.IntegrationTests.Persistence;

namespace SentinelForge.IntegrationTests.Security;

[Collection(PostgresTestGroup.Name)]
public sealed class AuthenticationTests(PostgresFixture db) : IDisposable
{
    private readonly ApiContext _api = new(db);

    public void Dispose() => _api.Dispose();

    private static async Task<string> DetailAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("detail").GetString()!;
    }

    // ---------- Cadastro ----------

    [Fact]
    public async Task Register_Valid_CreatesDeveloper_StoresOnlyHash_AndIgnoresClientSuppliedRole()
    {
        var email = ApiContext.NewEmail();

        using var response = await _api.Client.PostAsJsonAsync("/api/auth/register",
            new { name = "Ana", email, password = ApiContext.StrongPassword, role = "Administrator" });
        var raw = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var user = JsonSerializer.Deserialize<UserView>(raw, ApiContext.Json)!;
        Assert.Equal("Developer", user.Role);
        Assert.DoesNotContain("passwordHash", raw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(ApiContext.StrongPassword, raw, StringComparison.Ordinal);

        await using var read = db.CreateContext();
        var stored = await read.Users.AsNoTracking().SingleAsync(u => u.Id == user.Id);
        Assert.Equal(UserRole.Developer, stored.Role);
        Assert.NotEqual(ApiContext.StrongPassword, stored.PasswordHash);
        Assert.StartsWith("AQAAAA", stored.PasswordHash, StringComparison.Ordinal); // formato v3 do Identity (PBKDF2)
    }

    [Fact]
    public async Task Register_DuplicateEmail_ReturnsConflict_EvenWithDifferentCase()
    {
        var email = ApiContext.NewEmail();
        await _api.RegisterAsync(email);

        using var response = await _api.Client.PostAsJsonAsync("/api/auth/register",
            new { name = "Outra", email = email.ToUpperInvariant(), password = ApiContext.StrongPassword });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Theory]
    [InlineData("curta1!A")]
    [InlineData("semmaiusculas1234!")]
    [InlineData("SEMMINUSCULAS1234!")]
    [InlineData("SemDigitosAqui!!!!")]
    [InlineData("SemSimbolos123456A")]
    [InlineData("Password123456!x")]
    [InlineData("")]
    public async Task Register_WeakPassword_IsRejected(string password)
    {
        using var response = await _api.Client.PostAsJsonAsync("/api/auth/register",
            new { name = "Ana", email = ApiContext.NewEmail(), password });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("password", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Register_MissingPassword_OrInvalidEmail_IsRejected()
    {
        using var noPassword = await _api.Client.PostAsJsonAsync("/api/auth/register", new { name = "Ana", email = ApiContext.NewEmail() });
        using var badEmail = await _api.Client.PostAsJsonAsync("/api/auth/register", new { name = "Ana", email = "isto-nao-e-email", password = ApiContext.StrongPassword });

        Assert.Equal(HttpStatusCode.BadRequest, noPassword.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, badEmail.StatusCode);
    }

    // ---------- Login e JWT ----------

    [Fact]
    public async Task Login_Valid_IssuesSignedJwt_WithMinimalClaims_AndHardenedRefreshCookie()
    {
        var user = await _api.RegisterAsync();

        using var response = await _api.LoginRawAsync(user.Email, ApiContext.StrongPassword, refreshInBody: false);
        var body = await response.Content.ReadFromJsonAsync<TokenView>(ApiContext.Json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Bearer", body!.TokenType);
        Assert.Null(body.RefreshToken); // por padrão o refresh token só trafega no cookie

        var cookie = Assert.Single(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("sf_refresh=", StringComparison.Ordinal));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/api/auth", cookie, StringComparison.OrdinalIgnoreCase);

        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(body.AccessToken);
        Assert.Equal("HS256", jwt.Alg);
        Assert.Equal("SentinelForge", jwt.Issuer);
        Assert.Contains("SentinelForge.Api", jwt.Audiences);
        Assert.Equal(user.Id.ToString(), jwt.Subject);
        Assert.Equal("Developer", jwt.GetClaim("role").Value);
        Assert.InRange((jwt.ValidTo - jwt.ValidFrom).TotalMinutes, 14, 16);
        Assert.DoesNotContain(jwt.Claims, c => c.Type is "email" or "name" or "password" or "passwordHash");

        using var authorized = _api.NewClient(body.AccessToken);
        using var me = await authorized.GetAsync(new Uri($"/api/users/{user.Id}", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
    }

    [Fact]
    public async Task Login_Invalid_ReturnsIdenticalGenericResponse_ForWrongPasswordAndUnknownAccount()
    {
        var user = await _api.RegisterAsync();

        using var wrongPassword = await _api.LoginRawAsync(user.Email, "Wr0ng!Passw0rd#2026");
        using var unknown = await _api.LoginRawAsync(ApiContext.NewEmail(), ApiContext.StrongPassword);
        using var malformed = await _api.LoginRawAsync("não-é-email", ApiContext.StrongPassword);

        foreach (var response in new[] { wrongPassword, unknown, malformed })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("Invalid credentials.", await DetailAsync(response));
        }
    }

    [Fact]
    public async Task Login_RecordsSuccessAndFailureEvents_WithoutSecrets()
    {
        var user = await _api.RegisterAsync();
        (await _api.LoginRawAsync(user.Email, "Wr0ng!Passw0rd#2026")).Dispose();
        await _api.LoginAsync(user.Email);

        await using var read = db.CreateContext();
        var logs = await read.AuditLogs.AsNoTracking().Where(a => a.EntityId == user.Id).ToListAsync();

        Assert.Contains(logs, l => l.Action == AuditAction.LoginFailed);
        Assert.Contains(logs, l => l.Action == AuditAction.LoginSucceeded);
        Assert.All(logs, l =>
        {
            Assert.DoesNotContain(ApiContext.StrongPassword, l.NewValues ?? string.Empty, StringComparison.Ordinal);
            Assert.DoesNotContain("AQAAAA", l.NewValues ?? string.Empty, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Login_Lockout_BlocksEvenCorrectPassword_AfterTooManyFailures()
    {
        var user = await _api.RegisterAsync();

        for (var i = 0; i < 5; i++)
        {
            using var failure = await _api.LoginRawAsync(user.Email, "Wr0ng!Passw0rd#2026");
            Assert.Equal(HttpStatusCode.Unauthorized, failure.StatusCode);
        }

        using var correctButLocked = await _api.LoginRawAsync(user.Email, ApiContext.StrongPassword);

        Assert.Equal(HttpStatusCode.Unauthorized, correctButLocked.StatusCode);
        Assert.Equal("Invalid credentials.", await DetailAsync(correctButLocked)); // mesma resposta: não revela o bloqueio
        await using var read = db.CreateContext();
        Assert.NotNull((await read.Users.AsNoTracking().SingleAsync(u => u.Id == user.Id)).LockoutEnd);
    }

    [Fact]
    public async Task Login_RateLimit_ReturnsTooManyRequests_AfterThreshold()
    {
        using var limited = new ApiContext(db, new Dictionary<string, string?> { ["RateLimiting:AuthPermitLimit"] = "3" });

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 4; i++)
        {
            using var response = await limited.LoginRawAsync(ApiContext.NewEmail(), ApiContext.StrongPassword);
            statuses.Add(response.StatusCode);
        }

        Assert.Equal([HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.TooManyRequests], statuses);
    }

    // ---------- Validação do JWT / endpoints protegidos ----------

    [Theory]
    [InlineData("/api/applications")]
    [InlineData("/api/users")]
    [InlineData("/api/audit-logs")]
    public async Task ProtectedEndpoint_WithoutToken_ReturnsUnauthorized(string path)
    {
        using var response = await _api.Client.GetAsync(new Uri(path, UriKind.Relative));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Jwt_ExpiredInvalidWrongKeyUnsignedOrUnknownSession_AreRejected()
    {
        var session = await _api.NewSessionAsync();
        var tokens = new Dictionary<string, string>
        {
            ["expired (valid signature)"] = _api.ForgeToken(lifetime: TimeSpan.FromMinutes(-5), userId: session.Id),
            ["garbage"] = "isto.nao.eum.jwt",
            ["wrong signing key"] = _api.ForgeToken(signingKey: new string('k', 64), userId: session.Id),
            ["alg none"] = _api.ForgeToken(withoutSignature: true, userId: session.Id),
            ["valid signature, session never issued"] = _api.ForgeToken(userId: session.Id, role: "Developer"),
        };

        foreach (var (name, token) in tokens)
        {
            using var client = _api.NewClient(token);
            using var response = await client.GetAsync(new Uri("/api/applications", UriKind.Relative));
            Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{name} should be rejected but got {response.StatusCode}");
        }

        using var ok = await session.Client.GetAsync(new Uri("/api/applications", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    // ---------- Refresh token / logout ----------

    private async Task<HttpResponseMessage> RefreshAsync(string token) =>
        await _api.Client.PostAsJsonAsync("/api/auth/refresh", new { refreshToken = token });

    [Fact]
    public async Task Refresh_Valid_RotatesToken_AndStoresOnlyHash()
    {
        var user = await _api.RegisterAsync();
        var first = await _api.LoginAsync(user.Email);

        using var response = await RefreshAsync(first.RefreshToken!);
        var second = await response.Content.ReadFromJsonAsync<TokenView>(ApiContext.Json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotEqual(first.RefreshToken, second!.RefreshToken);
        Assert.NotEqual(first.AccessToken, second.AccessToken);

        using var authorized = _api.NewClient(second.AccessToken);
        using var ok = await authorized.GetAsync(new Uri("/api/applications", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        await using var read = db.CreateContext();
        var stored = await read.RefreshTokens.AsNoTracking().Where(t => t.UserId == user.Id).ToListAsync();
        Assert.Equal(2, stored.Count);
        Assert.DoesNotContain(stored, t => t.TokenHash == first.RefreshToken);
        Assert.Single(stored.Select(t => t.SessionId).Distinct());
    }

    [Fact]
    public async Task Refresh_WorksFromHttpOnlyCookie()
    {
        var user = await _api.RegisterAsync();
        var first = await _api.LoginAsync(user.Email);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/refresh");
        request.Headers.Add("Cookie", $"sf_refresh={first.RefreshToken}");
        using var response = await _api.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_ReusedToken_RevokesWholeSession()
    {
        var user = await _api.RegisterAsync();
        var first = await _api.LoginAsync(user.Email);

        using var legitimate = await RefreshAsync(first.RefreshToken!);
        var second = (await legitimate.Content.ReadFromJsonAsync<TokenView>(ApiContext.Json))!;

        using var replay = await RefreshAsync(first.RefreshToken!); // atacante reapresenta o token antigo
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);

        // A sessão inteira foi revogada: o token novo e o access token emitido junto também deixam de valer.
        using var afterReuse = await RefreshAsync(second.RefreshToken!);
        Assert.Equal(HttpStatusCode.Unauthorized, afterReuse.StatusCode);
        using var client = _api.NewClient(second.AccessToken);
        using var access = await client.GetAsync(new Uri("/api/applications", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Unauthorized, access.StatusCode);

        await using var read = db.CreateContext();
        Assert.Contains(await read.AuditLogs.AsNoTracking().Where(a => a.EntityId == user.Id).ToListAsync(),
            l => l.Action == AuditAction.RefreshTokenReuseDetected);
    }

    [Fact]
    public async Task Logout_RevokesSession_RefreshAndAccessTokensStopWorking()
    {
        var user = await _api.RegisterAsync();
        var tokens = await _api.LoginAsync(user.Email);

        using var logout = await _api.Client.PostAsJsonAsync("/api/auth/logout", new { refreshToken = tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var refresh = await RefreshAsync(tokens.RefreshToken!);
        Assert.Equal(HttpStatusCode.Unauthorized, refresh.StatusCode);

        using var client = _api.NewClient(tokens.AccessToken);
        using var access = await client.GetAsync(new Uri("/api/applications", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Unauthorized, access.StatusCode);

        // Idempotente e sem revelar nada sobre tokens desconhecidos.
        using var unknown = await _api.Client.PostAsJsonAsync("/api/auth/logout", new { refreshToken = "token-desconhecido" });
        Assert.Equal(HttpStatusCode.NoContent, unknown.StatusCode);
    }

    [Fact]
    public async Task Refresh_UnknownOrMissingToken_IsRejected()
    {
        using var unknown = await RefreshAsync("token-que-nunca-existiu");
        using var missing = await _api.Client.PostAsync(new Uri("/api/auth/refresh", UriKind.Relative), content: null);

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
    }

    [Fact]
    public async Task Refresh_ExpiredToken_IsRejected()
    {
        var user = await _api.RegisterAsync();
        var tokens = await _api.LoginAsync(user.Email);
        await using (var write = db.CreateContext())
        {
            await write.Database.ExecuteSqlRawAsync("UPDATE refresh_tokens SET \"ExpiresAt\" = now() - interval '1 minute' WHERE \"UserId\" = {0}", user.Id);
        }

        using var response = await RefreshAsync(tokens.RefreshToken!);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ---------- Robustez ----------

    [Fact]
    public async Task MalformedBody_ReturnsProblemDetails_WithoutLeakingInternals()
    {
        using var content = new StringContent("{ isto não é json", System.Text.Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
        using var response = await _api.Client.PostAsync(new Uri("/api/auth/login", UriKind.Relative), content);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain("Exception", body, StringComparison.Ordinal);
        Assert.DoesNotContain("SentinelForge.", body, StringComparison.Ordinal);
        Assert.DoesNotContain(" at ", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Responses_CarrySecurityHeaders_AndApiResponsesAreNotCached()
    {
        using var health = await _api.Client.GetAsync(new Uri("/health", UriKind.Relative));
        using var api = await _api.Client.GetAsync(new Uri("/api/applications", UriKind.Relative));

        Assert.Equal("nosniff", health.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", health.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("no-store", api.Headers.CacheControl!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cors_IsRestrictive_ByDefault_AndAllowsOnlyConfiguredOrigins()
    {
        static HttpRequestMessage Preflight(string origin)
        {
            var request = new HttpRequestMessage(HttpMethod.Options, "/api/auth/login");
            request.Headers.Add("Origin", origin);
            request.Headers.Add("Access-Control-Request-Method", "POST");
            return request;
        }

        using var denyByDefault = await _api.Client.SendAsync(Preflight("https://evil.example"));
        Assert.False(denyByDefault.Headers.Contains("Access-Control-Allow-Origin"));

        using var configured = new ApiContext(db, new Dictionary<string, string?> { ["Cors:AllowedOrigins:0"] = "https://app.example" });
        using var allowed = await configured.Client.SendAsync(Preflight("https://app.example"));
        using var other = await configured.Client.SendAsync(Preflight("https://evil.example"));

        Assert.Equal("https://app.example", allowed.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.False(other.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public void Startup_FailsFast_WithoutStrongJwtSigningKey()
    {
        var previous = Environment.GetEnvironmentVariable("Jwt__SigningKey");
        Environment.SetEnvironmentVariable("Jwt__SigningKey", null);
        try
        {
            using var factory = new ApiFactory(null, "curta");

            var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
            Assert.Contains("Jwt:SigningKey", ex.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("Jwt__SigningKey", previous);
        }
    }
}

