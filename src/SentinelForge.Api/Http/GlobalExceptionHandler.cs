using Microsoft.AspNetCore.Diagnostics;
using SentinelForge.Application.Common;
using SentinelForge.Domain.Common;

namespace SentinelForge.Api.Http;

/// <summary>
/// Converte exceções em respostas ProblemDetails sem expor detalhes internos (stack trace, SQL, nomes de tabela).
/// A exceção completa vai apenas para o log do servidor.
/// </summary>
internal sealed partial class GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger, IProblemDetailsService problemDetails)
    : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var (status, title, detail) = exception switch
        {
            // Rede de segurança: dado inaceitável para o banco (SQLSTATE classe 22, ex.: NUL em texto) é erro do
            // cliente, não 500. A validação de entrada deve barrar antes; isto evita vazar um 500 se algo escapar.
            _ when IsPostgresDataException(exception) => (StatusCodes.Status400BadRequest, "Bad request", "The request contains invalid data."),
            BadHttpRequestException => (StatusCodes.Status400BadRequest, "Bad request", "The request is malformed."),
            DomainException e => (StatusCodes.Status400BadRequest, "Validation failed", e.Message),
            ConflictException => (StatusCodes.Status409Conflict, "Conflict", "The request conflicts with the current state."),
            OperationCanceledException => (StatusCodes.Status400BadRequest, "Request cancelled", "The request was cancelled."),
            _ => (StatusCodes.Status500InternalServerError, "Server error", "An unexpected error occurred."),
        };

        if (status >= StatusCodes.Status500InternalServerError)
        {
            LogUnhandled(exception);
        }

        httpContext.Response.StatusCode = status;
        return await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = { Status = status, Title = title, Detail = detail },
        });
    }

    private static bool IsPostgresDataException(Exception exception)
    {
        for (var e = exception; e is not null; e = e.InnerException)
        {
            if (e is Npgsql.PostgresException { SqlState: { } state } && state.StartsWith("22", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Unhandled exception")]
    private partial void LogUnhandled(Exception exception);
}
