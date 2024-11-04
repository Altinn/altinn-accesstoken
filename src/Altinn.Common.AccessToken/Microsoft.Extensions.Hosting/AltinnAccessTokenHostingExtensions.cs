#if NET8_0_OR_GREATER

using Altinn.Common.AccessToken;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Extensions.Hosting;

/// <summary>
/// Extensions methods for adding access token services to the host.
/// </summary>
public static class AltinnAccessTokenHostingExtensions
{
    /// <summary>
    /// Adds the Altinn token handler to the host.
    /// </summary>
    /// <param name="builder">The host builder.</param>
    /// <param name="configurationSection">The configuration section path.</param>
    /// <param name="keyVaultConfigurationSection">The configuration section that holds configuration for keyvault.</param>
    /// <returns><paramref name="builder"/>.</returns>
    public static IHostApplicationBuilder AddAltinnTokenHandler(
        this IHostApplicationBuilder builder,
        string configurationSection = "AccessTokenSettings",
        string keyVaultConfigurationSection = "kvSetting")
    {
        builder.Services.AddOptions<AccessTokenSettings>()
            .BindConfiguration(configurationSection);

        var config = builder.Configuration.GetSection(keyVaultConfigurationSection);

        builder.Services.AddAltinnTokenHandler(config, builder.Environment);
        return builder;
    }
}

#endif
