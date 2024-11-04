using System;
using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Altinn.Common.AccessToken.KeyProvider;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessToken.Authorization;

/// <summary>
/// Authorization handler to verify that request contains access token
/// </summary>
internal partial class AccessTokenHandler
    : AuthorizationHandler<IAccessTokenRequirement>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger _logger;
    private readonly IPublicSigningKeyProvider _publicSigningKeyProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenHandler"/> class with the given parameters.
    /// </summary>
    public AccessTokenHandler(
        IHttpContextAccessor httpContextAccessor,
        ILogger<AccessTokenHandler> logger,
        IPublicSigningKeyProvider publicSigningKeyProvider)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _publicSigningKeyProvider = publicSigningKeyProvider;
    }

    /// <summary>
    /// Handles verification of AccessTokens. Enabled with Policy on API controllers 
    /// </summary>
    /// <param name="context">The current authorization handler context.</param>
    /// <param name="requirement">The requirement for the given operation.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, IAccessTokenRequirement requirement)
    {
        await Task.Yield();
        throw new NotImplementedException();
        ////StringValues tokens = GetAccessTokens();

        ////if (tokens.Count == 0 && _accessTokenSettings.DisableAccessTokenVerification)
        ////{
        ////    Log.TokenIsMissingAndFunctionIsTurnedOff(_logger);
        ////    context.Succeed(requirement);
        ////    return;
        ////}

        ////if (tokens.Count == 0)
        ////{
        ////    Log.ThereIsNoAccessToken(_logger);
        ////    return;
        ////}
        
        ////if (tokens.Count > 1)
        ////{
        ////    Log.ThereShouldBeOneAccessToken(_logger);
        ////    return;
        ////}

        ////try
        ////{
        ////    bool isValid = await ValidateAccessToken(tokens[0]!, requirement.ApprovedIssuers);

        ////    if (isValid)
        ////    {
        ////        context.Succeed(requirement);
        ////    }
        ////}
        ////catch (Exception ex)
        ////{
        ////    _logger.LogWarning(ex, "Validation of Access Token Failed");

        ////    if (_accessTokenSettings.DisableAccessTokenVerification)
        ////    {
        ////        context.Succeed(requirement);
        ////    }
        ////}
    }

    /////// <summary>
    /////// This validates the access token available in 
    /////// </summary>
    /////// <param name="token">The access token</param>
    /////// <param name="approvedIssuers">The list of approved issuers</param>
    /////// <returns></returns>
    ////private async Task<bool> ValidateAccessToken(string token, ImmutableArray<string> approvedIssuers)
    ////{
    ////    JwtSecurityTokenHandler validator = new JwtSecurityTokenHandler();

    ////    if (!validator.CanReadToken(token))
    ////    {
    ////        return false;
    ////    }

    ////    // Read JWT token to extract Issuer
    ////    JwtSecurityToken jwt = validator.ReadJwtToken(token);

    ////    // When no exact match on token issuer against approved issuers
    ////    if (!approvedIssuers.IsDefaultOrEmpty && !approvedIssuers.Contains(jwt.Issuer))
    ////    {
    ////        return false;
    ////    }

    ////    TokenValidationParameters validationParameters = await GetTokenValidationParameters(jwt.Issuer);

    ////    SecurityToken validatedToken;
    ////    try
    ////    {
    ////        ClaimsPrincipal principal = validator.ValidateToken(token, validationParameters, out validatedToken);
    ////        SetAccessTokenCredential(validatedToken.Issuer, principal);
    ////        return true;
    ////    }
    ////    catch (Exception ex)
    ////    {
    ////        Log.FailedToValidateTokenFromIssuer(_logger, jwt.Issuer, ex);
    ////    }

    ////    return false;
    ////}

    ////private async Task<TokenValidationParameters> GetTokenValidationParameters(string issuer)
    ////{
    ////    TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
    ////    {
    ////        ValidateIssuerSigningKey = true,
    ////        ValidateIssuer = false,
    ////        ValidateAudience = false,
    ////        RequireExpirationTime = true,
    ////        ValidateLifetime = true,
    ////        ClockSkew = new TimeSpan(0, 0, 10)
    ////    };

    ////    tokenValidationParameters.IssuerSigningKeys = await _publicSigningKeyProvider.GetSigningKeys(issuer);
    ////    return tokenValidationParameters;
    ////}

    ////private StringValues GetAccessTokens()
    ////{
    ////    var ctx = _httpContextAccessor.HttpContext;
    ////    if (ctx is null)
    ////    {
    ////        return StringValues.Empty;
    ////    }

    ////    if (ctx.Request.Headers.TryGetValue(_accessTokenSettings.AccessTokenHeaderId, out var value))
    ////    {
    ////        return value;
    ////    }

    ////    return StringValues.Empty;
    ////}

    ////private void SetAccessTokenCredential(string issuer, ClaimsPrincipal claimsPrincipal)
    ////{
    ////    string appClaim = string.Empty;
    ////    foreach (Claim claim in claimsPrincipal.Claims)
    ////    {
    ////        if (claim.Type.Equals(AccessTokenClaimTypes.App))
    ////        {
    ////            appClaim = claim.Value;
    ////            break;
    ////        }
    ////    }

    ////    _httpContextAccessor.HttpContext!.Items.Add(_accessTokenSettings.AccessTokenHttpContextId, $"{issuer}/{appClaim}");
    ////}

    ////private static partial class Log
    ////{
    ////    [LoggerMessage(0, LogLevel.Information, "Token is missing and function is turned off")]
    ////    public static partial void TokenIsMissingAndFunctionIsTurnedOff(ILogger logger);

    ////    [LoggerMessage(1, LogLevel.Information, "There is no access token")]
    ////    public static partial void ThereIsNoAccessToken(ILogger logger);

    ////    [LoggerMessage(2, LogLevel.Warning, "There should only be one access token")]
    ////    public static partial void ThereShouldBeOneAccessToken(ILogger logger);

    ////    [LoggerMessage(3, LogLevel.Warning, "Failed to validate token from issuer {Issuer}.")]
    ////    public static partial void FailedToValidateTokenFromIssuer(ILogger logger, string issuer, Exception? exception);
    ////}
}
