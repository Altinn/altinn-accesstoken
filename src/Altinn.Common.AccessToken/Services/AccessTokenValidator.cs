using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessToken.Services;

/// <summary>
/// Service for access token validation
/// </summary>
public class AccessTokenValidator : IAccessTokenValidator
{
    private readonly IPublicSigningKeyProvider _publicSigningKeyProvider;
    private readonly ILogger<IAccessTokenValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenValidator"/> class.
    /// </summary>
    /// <param name="publicSigningKeyProvider">The signing keys resolver</param>
    /// <param name="logger">The logger</param>
    public AccessTokenValidator(
        IPublicSigningKeyProvider publicSigningKeyProvider,
        ILogger<IAccessTokenValidator> logger)
    {
        _publicSigningKeyProvider = publicSigningKeyProvider;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<bool> Validate(string token)
    {
        JwtSecurityTokenHandler validator = new JwtSecurityTokenHandler();

        if (!validator.CanReadToken(token))
        {
            return false;
        }

        JwtSecurityToken jwt = validator.ReadJwtToken(token);
        TokenValidationParameters validationParameters = await GetTokenValidationParameters(jwt.Issuer);

        TokenValidationResult validationResult = await validator.ValidateTokenAsync(token, validationParameters);

        if (validationResult.IsValid)
        {
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
            ClockSkew = TimeSpan.FromSeconds(60)
        };

        tokenValidationParameters.IssuerSigningKeys = await _publicSigningKeyProvider.GetSigningKeys(issuer);
        return tokenValidationParameters;
    }
}
