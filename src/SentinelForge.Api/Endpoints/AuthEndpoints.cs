using Microsoft.AspNetCore.RateLimiting;
using SentinelForge.Api.Http;
using SentinelForge.Application.Contracts;
using SentinelForge.Application.Services;

namespace SentinelForge.Api.Endpoints;

internal static class AuthEndpoints
{
    public const string RefreshCookie = "sf_refresh";
    public const string RateLimitPolicy = "auth";
    private const string CookiePath = "/api/auth";
    private const string DeliveryHeader = "X-Token-Delivery";

    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth").AllowAnonymous().RequireRateLimiting(RateLimitPolicy).WithTags("Auth");

        group.MapPost("/register", async (RegisterRequest request, AuthService auth, CancellationToken ct) =>
            (await auth.RegisterAsync(request, ct)).ToHttp(user => Results.Created($"/api/users/{user.Id}", user)));

        group.MapPost("/login", async (LoginRequest request, AuthService auth, HttpContext http, CancellationToken ct) =>
        {
            var result = await auth.LoginAsync(request, ct);
            return result.IsSuccess ? Issue(http, result.Value!) : result.Error!.ToHttp();
        });

        group.MapPost("/refresh", async (RefreshRequest? body, AuthService auth, HttpContext http, CancellationToken ct) =>
        {
            var result = await auth.RefreshAsync(body?.RefreshToken ?? http.Request.Cookies[RefreshCookie], ct);
            if (result.IsSuccess)
            {
                return Issue(http, result.Value!);
            }

            http.Response.Cookies.Delete(RefreshCookie, CookieOptions());
            return result.Error!.ToHttp();
        });

        group.MapPost("/logout", async (RefreshRequest? body, AuthService auth, HttpContext http, CancellationToken ct) =>
        {
            await auth.LogoutAsync(body?.RefreshToken ?? http.Request.Cookies[RefreshCookie], ct);
            http.Response.Cookies.Delete(RefreshCookie, CookieOptions());
            return Results.NoContent();
        });

        return app;
    }

    private static CookieOptions CookieOptions(DateTime? expires = null) => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = CookiePath,
        IsEssential = true,
        Expires = expires is null ? null : new DateTimeOffset(expires.Value, TimeSpan.Zero),
    };

    private static IResult Issue(HttpContext http, AuthTokens tokens)
    {
        http.Response.Cookies.Append(RefreshCookie, tokens.RefreshToken, CookieOptions(tokens.RefreshTokenExpiresAt));

        var inBody = string.Equals(http.Request.Headers[DeliveryHeader], "body", StringComparison.OrdinalIgnoreCase);
        return Results.Ok(new TokenResponse(
            tokens.AccessToken,
            "Bearer",
            tokens.AccessTokenExpiresAt,
            tokens.RefreshTokenExpiresAt,
            inBody ? tokens.RefreshToken : null));
    }
}
