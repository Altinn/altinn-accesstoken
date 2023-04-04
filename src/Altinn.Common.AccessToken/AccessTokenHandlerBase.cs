using System;
using System.IdentityModel.Tokens.Jwt;
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

namespace Altinn.Common.AccessToken
{
    /// <summary>
    /// Base class authorization handler to verify that request contains access token
    /// </summary>
    public class AccessTokenHandlerBase<T> : AuthorizationHandler<T>
        where T : IAuthorizationRequirement
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger _logger;
        private readonly AccessTokenSettings _accessTokenSettings;
        private readonly ISigningKeysResolver _signingKeysResolver;

        /// <summary>
        /// Initializes a new instance of the <see cref="AccessTokenHandlerBase{T}"/> class.
        /// </summary>
        /// <param name="httpContextAccessor">Default httpContext accessor</param>
        /// <param name="logger">The logger</param>
        /// <param name="accessTokenSettings">The access token settings</param>
        /// <param name="signingKeysResolver">The resolver for signing keys</param>
        public AccessTokenHandlerBase(
            IHttpContextAccessor httpContextAccessor,
            ILogger<AccessTokenHandlerBase<T>> logger,
            IOptions<AccessTokenSettings> accessTokenSettings,
            ISigningKeysResolver signingKeysResolver)
        {
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
            _accessTokenSettings = accessTokenSettings.Value;
            _signingKeysResolver = signingKeysResolver;
        }

        /// <summary>
        /// Handles verification of AccessTokens. Enabled with Policy on API controllers 
        /// </summary>
        /// <param name="context">The context</param>
        /// <param name="requirement">The requirement for the given operation</param>
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, T requirement)
        {
            StringValues tokens = GetAccessTokens();
            if (tokens.Count != 1 && _accessTokenSettings.DisableAccessTokenVerification)
            {
                _logger.LogWarning("Token is missing and function is turned off");
                context.Succeed(requirement);
                return;
            }

            // It should only be one accesss token
            if (tokens.Count != 1)
            {
                _logger.LogWarning("Missing Access token");
                return;
            }

            bool isValid;
            try
            {
                isValid = await ValidateAccessToken(tokens[0]);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Validation of Access Token Failed");
                if (!_accessTokenSettings.DisableAccessTokenVerification)
                {
                    return;
                }
                else
                {
                    context.Succeed(requirement);
                    return;
                }
            }

            if (isValid)
            {
                context.Succeed(requirement);
            }
        }

        /// <summary>
        /// This validates the access token available in 
        /// </summary>
        /// <param name="token">The access token</param>
        /// <returns></returns>
        private async Task<bool> ValidateAccessToken(string token)
        {
            JwtSecurityTokenHandler validator = new JwtSecurityTokenHandler();

            if (!validator.CanReadToken(token))
            {
                return false;
            }

            // Read JWT token to extract Issuer
            JwtSecurityToken jwt = validator.ReadJwtToken(token);
            TokenValidationParameters validationParameters = await GetTokenValidationParameters(jwt.Issuer);

            SecurityToken validatedToken;
            try
            {
                ClaimsPrincipal prinicpal = validator.ValidateToken(token, validationParameters, out validatedToken);
                SetAccessTokenCredential(validatedToken.Issuer, prinicpal);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to validate token from issuer {Issuer}.", jwt.Issuer);
            }

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

            tokenValidationParameters.IssuerSigningKeys = await _signingKeysResolver.GetSigningKeys(issuer);
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

        private void SetAccessTokenCredential(string issuer, ClaimsPrincipal claimsPrincipal)
        {
            string appClaim = string.Empty;
            foreach (var claim in claimsPrincipal.Claims)
            {
                if (claim.Type.Equals(AccessTokenClaimTypes.App))
                {
                    appClaim = claim.Value;
                    break;
                }
            }

            _httpContextAccessor.HttpContext.Items.Add(_accessTokenSettings.AccessTokenHttpContextId, issuer + "/" + appClaim);
        }
    }
}
