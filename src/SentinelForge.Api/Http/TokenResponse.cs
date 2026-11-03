using System.Text.Json.Serialization;

namespace SentinelForge.Api.Http;

/// <param name="RefreshToken">
/// Só presente quando o cliente pede entrega no corpo (cabeçalho X-Token-Delivery: body). Por padrão o refresh
/// token trafega apenas em cookie HttpOnly.
/// </param>
internal sealed record TokenResponse(
    string AccessToken,
    string TokenType,
    DateTime ExpiresAt,
    DateTime RefreshTokenExpiresAt,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RefreshToken);

internal sealed record RefreshRequest(string? RefreshToken);

internal sealed record ChangeRoleRequest(SentinelForge.Domain.Enums.UserRole Role);


