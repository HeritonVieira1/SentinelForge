using SentinelForge.Application.Common;

namespace SentinelForge.Api.Http;

internal static class ResultExtensions
{
    public static IResult ToHttp<T>(this Result<T> result, Func<T, IResult>? onSuccess = null) =>
        result.IsSuccess
            ? onSuccess is null ? Results.Ok(result.Value) : onSuccess(result.Value!)
            : result.Error!.ToHttp();

    public static IResult ToHttp(this Result result, Func<IResult>? onSuccess = null) =>
        result.IsSuccess ? (onSuccess?.Invoke() ?? Results.NoContent()) : result.Error!.ToHttp();

    public static IResult ToHttp(this ResultError error)
    {
        IResult problem = error.Kind switch
        {
            ErrorKind.Validation when error.Details is { } details =>
                Results.ValidationProblem(details.ToDictionary(kv => kv.Key, kv => kv.Value), title: "One or more validation errors occurred."),
            ErrorKind.Validation => Results.Problem(error.Message, statusCode: StatusCodes.Status400BadRequest, title: "Validation failed"),
            ErrorKind.Unauthorized => Results.Problem(error.Message, statusCode: StatusCodes.Status401Unauthorized, title: "Unauthorized"),
            ErrorKind.Forbidden => Results.Problem(error.Message, statusCode: StatusCodes.Status403Forbidden, title: "Forbidden"),
            ErrorKind.NotFound => Results.Problem(error.Message, statusCode: StatusCodes.Status404NotFound, title: "Not found"),
            ErrorKind.Conflict => Results.Problem(error.Message, statusCode: StatusCodes.Status409Conflict, title: "Conflict"),
            ErrorKind.TooManyRequests => Results.Problem(error.Message, statusCode: StatusCodes.Status429TooManyRequests, title: "Too many requests"),
            ErrorKind.Unavailable => Results.Problem(error.Message, statusCode: StatusCodes.Status503ServiceUnavailable, title: "Service unavailable"),
            _ => Results.Problem(statusCode: StatusCodes.Status500InternalServerError),
        };

        return error.RetryAfterSeconds is { } seconds ? new WithRetryAfter(problem, seconds) : problem;
    }

    private sealed class WithRetryAfter(IResult inner, int seconds) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return inner.ExecuteAsync(httpContext);
        }
    }
}
