using System.Threading.Tasks;

using Altinn.Common.AccessToken.Configuration;
using Altinn.Common.AccessToken.Services;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Altinn.Common.AccessToken
{
    /// <summary>
    /// Authorization handler to verify that request contains access token
    /// </summary>
    public class AccessTokenHandler<T> : AccessTokenHandlerBase<T>
    where T : IAuthorizationRequirement
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AccessTokenHandler{T}"/> class.
        /// </summary>
        /// <param name="httpContextAccessor">Default httpContext accessor</param>
        /// <param name="logger">The logger</param>
        /// <param name="accessTokenSettings">The access token settings</param>
        /// <param name="signingKeysResolver">The resolver for signing keys</param>
        public AccessTokenHandler(
            IHttpContextAccessor httpContextAccessor,
            ILogger<AccessTokenHandlerBase<T>> logger,
            IOptions<AccessTokenSettings> accessTokenSettings,
            ISigningKeysResolver signingKeysResolver)
            : base(
                httpContextAccessor,
                logger,
                accessTokenSettings,
                signingKeysResolver)
        {
        }

        /// <inheritdoc/>
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, T requirement)
        {
            await base.HandleRequirementAsync(context, requirement);
        }
    }
}
