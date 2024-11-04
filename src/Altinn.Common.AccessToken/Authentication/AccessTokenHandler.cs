using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessToken.Authentication;

/// <summary>
/// <see cref="IAuthenticationHandler"/> for altinn platform access tokens.
/// </summary>
internal sealed partial class AccessTokenHandler
    : AuthenticationHandler<AccessTokenOptions>
{
    private static readonly AuthenticateResult TokenHandlerUnableToValidate = AuthenticateResult.Fail("No TokenHandler was able to validate the token.");
    private static readonly AuthenticateResult MultipleTokens = AuthenticateResult.Fail("Multiple access tokens provided");

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenHandler"/> class.
    /// </summary>
    public AccessTokenHandler(
        IOptionsMonitor<AccessTokenOptions> optionsMonitor,
        ILoggerFactory loggerFactory,
        UrlEncoder urlEncoder)
        : base(optionsMonitor, loggerFactory, urlEncoder)
    {
    }

    private new AccessTokenEvents Events => (AccessTokenEvents)base.Events!;

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Give application opportunity to find from a different location, adjust, or reject token.
        var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);

        await Events.MessageReceivedAsync(messageReceivedContext);

        if (messageReceivedContext.Result is not null)
        {
            return messageReceivedContext.Result;
        }

        var token = messageReceivedContext.Token;
        if (string.IsNullOrEmpty(token))
        {
            var tokens = GetAccessTokenCandidates();

            if (tokens.Count == 0)
            {
                Log.ThereIsNoAccessToken(Logger);
                return AuthenticateResult.NoResult();
            }

            if (tokens.Count > 1)
            {
                Log.ThereShouldBeOneAccessToken(Logger);
                return MultipleTokens;
            }

            token = tokens[0]!;
        }

        TokenValidationParameters tokenValidationParameters = new()
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = false,
            ValidateAudience = false,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(10),
        };

        List<Exception>? validationFailures = null;
        SecurityToken? validatedToken = null;
        ClaimsPrincipal? principal = null;

        foreach (var tokenHandler in Options.TokenHandlers)
        {
            try
            {
                var securityToken = tokenHandler.ReadToken(token);
                tokenValidationParameters.IssuerSigningKeys = await Options.PublicSigningKeyProvider.GetSigningKeys(securityToken.Issuer, Context.RequestAborted);

                var tokenValidationResult = await tokenHandler.ValidateTokenAsync(securityToken, tokenValidationParameters);
                if (tokenValidationResult.IsValid)
                {
                    principal = new(tokenValidationResult.ClaimsIdentity);
                    validatedToken = tokenValidationResult.SecurityToken;
                    break;
                }
                else if (tokenValidationResult.Exception is not null)
                {
                    validationFailures ??= new(1);
                    RecordTokenValidationError(
                        tokenValidationResult.Exception ?? new SecurityTokenValidationException($"The TokenHandler: '{tokenHandler}', was unable to validate the Token."),
                        validationFailures);
                }
            }
            catch (Exception ex)
            {
                validationFailures ??= new(1);
                RecordTokenValidationError(ex, validationFailures);
            }
        }

        if (principal is not null && validatedToken is not null)
        {
            Log.TokenValidationSucceeded(Logger);

            var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options, validatedToken)
            {
                Principal = principal,
                Properties =
                {
                    ExpiresUtc = GetSafeDateTime(validatedToken.ValidTo),
                    IssuedUtc = GetSafeDateTime(validatedToken.ValidFrom),
                },
            };

            await Events.TokenValidated(tokenValidatedContext);
            if (tokenValidatedContext.Result != null)
            {
                return tokenValidatedContext.Result;
            }

            if (Options.SaveToken)
            {
                tokenValidatedContext.Properties.StoreTokens([
                    new AuthenticationToken { Name = "access_token", Value = token }
                ]);
            }

            tokenValidatedContext.Success();
            return tokenValidatedContext.Result!;
        }
        
        if (validationFailures is not null)
        {
            var exn = (validationFailures.Count == 1) ? validationFailures[0] : new AggregateException(validationFailures);
            var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options, exn);

            await Events.AuthenticationFailed(authenticationFailedContext);
            if (authenticationFailedContext.Result != null)
            {
                return authenticationFailedContext.Result;
            }

            return AuthenticateResult.Fail(authenticationFailedContext.Exception);
        }

        return TokenHandlerUnableToValidate;
    }

    private StringValues GetAccessTokenCandidates()
    {
        if (Request.Headers.TryGetValue(Options.AccessTokenHeaderId, out var value))
        {
            return value;
        }

        return StringValues.Empty;
    }

    private void RecordTokenValidationError(Exception exception, List<Exception> exceptions)
    {
        Log.TokenValidationFailed(Logger, exception);
        exceptions.Add(exception);
    }

    private static DateTime? GetSafeDateTime(DateTime dateTime)
    {
        // Assigning DateTime.MinValue or default(DateTime) to a DateTimeOffset when in a UTC+X timezone will throw
        // Since we don't really care about DateTime.MinValue in this case let's just set the field to null
        if (dateTime == DateTime.MinValue)
        {
            return null;
        }

        return dateTime;
    }

    private static partial class Log
    {
        [LoggerMessage(0, LogLevel.Information, "Token is missing and function is turned off.")]
        public static partial void TokenIsMissingAndFunctionIsTurnedOff(ILogger logger);

        [LoggerMessage(1, LogLevel.Debug, "There is no access token.")]
        public static partial void ThereIsNoAccessToken(ILogger logger);

        [LoggerMessage(2, LogLevel.Warning, "There should only be one access token.")]
        public static partial void ThereShouldBeOneAccessToken(ILogger logger);

        [LoggerMessage(3, LogLevel.Warning, "Failed to validate token from issuer {Issuer}.")]
        public static partial void FailedToValidateTokenFromIssuer(ILogger logger, string issuer, Exception? exception);

        [LoggerMessage(4, LogLevel.Information, "Failed to validate the token.")]
        public static partial void TokenValidationFailed(ILogger logger, Exception exception);

        [LoggerMessage(5, LogLevel.Debug, "Successfully validated the token.")]
        public static partial void TokenValidationSucceeded(ILogger logger);
    }
}
