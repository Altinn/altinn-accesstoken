using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Altinn.Common.AccessToken;
using Altinn.Common.AccessToken.KeyProvider;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Altinn.Common.AccessTokenClient;

/// <summary>
/// Access token generator creating access tokens for accessing platform components
/// </summary>
internal partial class AccessTokenGenerator 
    : IAccessTokenGenerator
{
    private readonly IOptionsMonitor<AccessTokenGeneratorSettings> _accessTokenSettings;
    private readonly ISigningCredentialsProvider _signingCredentialsProvider;
    private readonly ILogger _logger;
    private readonly IMemoryCache _memoryCache;

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenGenerator"/> class.
    /// </summary>
    public AccessTokenGenerator(
        ILogger<AccessTokenGenerator> logger,
        IOptionsMonitor<AccessTokenGeneratorSettings> accessTokenSettings, 
        ISigningCredentialsProvider signingKeysResolver,
        IMemoryCache memoryCache)
    {
        _memoryCache = memoryCache;
        _accessTokenSettings = accessTokenSettings;
        _signingCredentialsProvider = signingKeysResolver;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<string?> GenerateAccessToken(string issuer, string app, CancellationToken cancellationToken = default)
    {
        SigningCredentials credentials;
        try
        {
            credentials = await _signingCredentialsProvider.GetSigningCredentials(cancellationToken);
        }
        catch (OperationCanceledException ex) when (ex.CancellationToken == cancellationToken)
        {
            throw;
        }
        catch (Exception ex)
        {
            Log.FailedToGetSigningCredentials(_logger, ex);
            return null;
        }
        
        return GetOrCreate(issuer, app, credentials);
    }

    /// <inheritdoc/>
    public Task<string?> GenerateAccessToken(string issuer, string app, X509Certificate2 certificate, CancellationToken cancellationToken = default)
    {
        return Task.FromResult<string?>(GetOrCreate(issuer, app, new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256)));
    }

    private string? GetOrCreate(string issuer, string app, SigningCredentials signingCredentials)
    {
        var cacheKey = new CacheKey(issuer, app, signingCredentials.Kid);

        try
        {
            return _memoryCache.GetOrCreate(cacheKey, entry =>
            {
                var settings = _accessTokenSettings.CurrentValue;

                ClaimsIdentity identity = new("AccessToken");
                if (!string.IsNullOrEmpty(app))
                {
                    identity.AddClaim(new(AccessTokenClaimTypes.App, app, ClaimValueTypes.String, issuer));
                }

                ClaimsPrincipal principal = new(identity);
                JwtSecurityTokenHandler tokenHandler = new();
                SecurityTokenDescriptor tokenDescriptor = new()
                {
                    Subject = new ClaimsIdentity(principal.Identity),
                    NotBefore = DateTime.UtcNow.AddSeconds(settings.ValidFromAdjustmentSeconds),
                    Expires = DateTime.UtcNow.AddSeconds(settings.TokenLifetimeInSeconds),
                    SigningCredentials = signingCredentials,
                    Audience = "platform.altinn.no",
                    Issuer = issuer,
                };

                SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
                entry.SetPriority(CacheItemPriority.NeverRemove);
                entry.SetAbsoluteExpiration(token.ValidTo.AddMinutes(-1));

                return tokenHandler.WriteToken(token);
            });
        }
        catch (Exception ex) 
        {
            Log.FailedToGenerateAccessToken(_logger, ex);
            return null;
        }
    }

    private sealed record CacheKey(string Issuer, string App, string Kid);

    private static partial class Log
    {
        [LoggerMessage(0, LogLevel.Warning, "Failed to get signing credentials")]
        public static partial void FailedToGetSigningCredentials(ILogger logger, Exception ex);

        [LoggerMessage(1, LogLevel.Warning, "Failed to generate access token")]
        public static partial void FailedToGenerateAccessToken(ILogger logger, Exception ex);
    }
}
