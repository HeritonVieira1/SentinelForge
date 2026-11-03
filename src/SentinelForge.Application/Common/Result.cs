namespace SentinelForge.Application.Common;

public enum ErrorKind
{
    Validation,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
    TooManyRequests,
}

public sealed record ResultError(ErrorKind Kind, string Message, IReadOnlyDictionary<string, string[]>? Details = null, int? RetryAfterSeconds = null);

public class Result
{
    protected Result(ResultError? error) => Error = error;

    public ResultError? Error { get; }

    public bool IsSuccess => Error is null;

    public static Result Success() => new(null);

    public static Result Failure(ErrorKind kind, string message) => new(new ResultError(kind, message));

    public static Result<T> Success<T>(T value) => new(value, null);

    public static Result<T> Failure<T>(ResultError error) => new(default, error);

    public static Result<T> Failure<T>(ErrorKind kind, string message) => new(default, new ResultError(kind, message));
}

public sealed class Result<T> : Result
{
    internal Result(T? value, ResultError? error)
        : base(error) => Value = value;

    public T? Value { get; }
}
public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Page, int PageSize, int TotalCount);

/// <summary>Violação de unicidade detectada na persistência (ex.: e-mail duplicado).</summary>
public sealed class ConflictException : Exception
{
    public ConflictException()
    {
    }

    public ConflictException(string message)
        : base(message)
    {
    }

    public ConflictException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}


