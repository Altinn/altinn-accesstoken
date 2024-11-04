using System.IO;
using Altinn.Common.AccessToken.KeyProvider;
using Altinn.Common.AccessTokenClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Dependency injection extensions for access token.
/// </summary>
public static class AltinnAccessTokenClientDependencyInjectionExtensions
{
    /// <summary>
    /// Adds a <see cref="IAccessTokenGenerator"/> to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The current configuration.</param>
    /// <param name="environment">The current environment.</param>
    /// <returns><paramref name="services"/>.</returns>
    public static IServiceCollection AddAltinnTokenGenerator(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        services.AddAltinnTokenValidator(configuration, environment);

        if (services.Contains(Marker.ServiceDescriptor))
        {
            return services;
        }

        services.Add(Marker.ServiceDescriptor);

        services.AddOptions<AccessTokenGeneratorSettings>().Bind(configuration);
        var certificatePath = configuration.GetValue<string>("CertificatePath");
        if (string.IsNullOrEmpty(certificatePath))
        {
            // backward compatibility
            var basePath = Directory.GetParent(Directory.GetCurrentDirectory())?.FullName;
            var keysFolder = configuration.GetValue("AccessTokenSigningKeysFolder", defaultValue: "accesstoken/");
            var certificateFileName = configuration.GetValue("AccessTokenSigningCertificateFileName", defaultValue: "accesstokencredentials.pfx");
            certificatePath = $"{basePath}{keysFolder}{certificateFileName}";
        }

        if (File.Exists(certificatePath))
        {
            services.AddOptions<LocalSigningCredentialsProvider.Settings>()
                .Configure(opts => opts.CertificatePath = certificatePath);

            services.TryAddSingleton<ISigningCredentialsProvider, LocalSigningCredentialsProvider>();
        }

        services.TryAddSingleton<IAccessTokenGenerator, AccessTokenGenerator>();
        return services;
    }

    private sealed class Marker
    {
        public static readonly ServiceDescriptor ServiceDescriptor = ServiceDescriptor.Singleton<Marker, Marker>();
    }
}
