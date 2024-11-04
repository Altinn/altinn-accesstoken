using System;
using Altinn.Common.AccessToken.Authentication;
using Microsoft.AspNetCore.Authentication;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for <see cref="AuthenticationBuilder"/>.
/// </summary>
public static class AltinnAccessTokenAuthenticationBuilderExtensions
{
    /// <summary>
    /// Adds access token authentication. The default scheme is specified by <see cref="AccessTokenDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddAltinnAccessToken(this AuthenticationBuilder builder)
        => builder.AddAltinnAccessToken(AccessTokenDefaults.AuthenticationScheme);

    /// <summary>
    /// Adds access token authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddAltinnAccessToken(this AuthenticationBuilder builder, string authenticationScheme)
        => builder.AddAltinnAccessToken(authenticationScheme, static _ => { });

    /// <summary>
    /// Adds access token authentication. The default scheme is specified by <see cref="AccessTokenDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configure">Action used to configure the bearer token authentication options.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddAltinnAccessToken(this AuthenticationBuilder builder, Action<AccessTokenOptions> configure)
        => builder.AddAltinnAccessToken(AccessTokenDefaults.AuthenticationScheme, configure);

    /// <summary>
    /// Adds access token authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configure">Action used to configure the bearer token authentication options.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddAltinnAccessToken(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<AccessTokenOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(authenticationScheme);
        ArgumentNullException.ThrowIfNull(configure);

        return builder.AddScheme<AccessTokenOptions, AccessTokenHandler>(authenticationScheme, configure);
    }
}
