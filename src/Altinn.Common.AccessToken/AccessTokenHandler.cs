using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using Altinn.Common.AccessToken.Configuration;
using Altinn.Common.AccessToken.Constants;
using Altinn.Common.AccessToken.Services;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessToken;

/// <summary>
/// Authorization handler to verify that request contains access token
/// </summary>
public class AccessTokenHandler : AuthorizationHandler<IAccessTokenRequirement>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger _logger;
    private readonly AccessTokenSettings _accessTokenSettings;
    private readonly IPublicSigningKeyProvider _publicSigningKeyProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenHandler"/> class with the given parameters.
    /// </summary>
    /// <param name="httpContextAccessor">A service that provides access to the current HttpContext.</param>
    /// <param name="logger">A logger</param>
    /// <param name="accessTokenSettings">The access token settings</param>
    /// <param name="publicSigningKeyProvider">The resolver for signing keys</param>
    public AccessTokenHandler(
        IHttpContextAccessor httpContextAccessor,
        ILogger<AccessTokenHandler> logger,
        IOptions<AccessTokenSettings> accessTokenSettings,
        IPublicSigningKeyProvider publicSigningKeyProvider)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _accessTokenSettings = accessTokenSettings.Value;
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
        StringValues tokens = GetAccessTokens();

        if (tokens.Count != 1 && _accessTokenSettings.DisableAccessTokenVerification)
        {
            _logger.LogWarning("Token is missing and function is turned of");
            context.Succeed(requirement);
            return;
        }

        if (tokens.Count != 1)
        {
            _logger.LogWarning("There should be one accesss token");
            return;
        }

        try
        {
            bool isValid = await ValidateAccessToken(tokens[0], requirement.ApprovedIssuers);

            if (isValid)
            {
                context.Succeed(requirement);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Validation of Access Token Failed");

            if (_accessTokenSettings.DisableAccessTokenVerification)
            {
                context.Succeed(requirement);
            }
        }
    }

    /// <summary>
    /// This validates the access token available in 
    /// </summary>
    /// <param name="token">The access token</param>
    /// <param name="approvedIssuers">The list of approved issuers</param>
    /// <returns></returns>
    private async Task<bool> ValidateAccessToken(string token, string[] approvedIssuers)
    {
        JwtSecurityTokenHandler validator = new JwtSecurityTokenHandler();

        if (!validator.CanReadToken(token))
        {
            return false;
        }

        // Read JWT token to extract Issuer
        JwtSecurityToken jwt = validator.ReadJwtToken(token);

        // When no exact match on token issuer against approved issuers
        if (approvedIssuers.Length > 0 && Array.IndexOf(approvedIssuers, jwt.Issuer) < 0)
        {
            return false;
        }

        TokenValidationParameters validationParameters = await GetTokenValidationParameters(jwt.Issuer);

        TokenValidationResult validationResult = await validator.ValidateTokenAsync(token, validationParameters);

        if (validationResult.IsValid)
        {
            SetAccessTokenCredential(validationResult.Issuer, validationResult.ClaimsIdentity.Claims);
            return true;
        }

        _logger.LogWarning(validationResult.Exception, "Failed to validate token from issuer {Issuer}.", jwt.Issuer);
        return false;
    }

    private async Task<TokenValidationParameters> GetTokenValidationParameters(string issuer)
    {
        TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = false,
            ValidateAudience = false,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        tokenValidationParameters.IssuerSigningKeys = await _publicSigningKeyProvider.GetSigningKeys(issuer);
        return tokenValidationParameters;
    }

    private StringValues GetAccessTokens()
    {
        if (_httpContextAccessor.HttpContext.Request.Headers.ContainsKey(_accessTokenSettings.AccessTokenHeaderId))
        {
            return _httpContextAccessor.HttpContext.Request.Headers[_accessTokenSettings.AccessTokenHeaderId];
        }

        return StringValues.Empty;
    }

    private void SetAccessTokenCredential(string issuer, IEnumerable<Claim> claims)
    {
        string appClaim = claims.FirstOrDefault(claim => claim.Type.Equals(AccessTokenClaimTypes.App))?.Value;

        _httpContextAccessor.HttpContext.Items.Add(_accessTokenSettings.AccessTokenHttpContextId, issuer + "/" + appClaim);
    }
}
