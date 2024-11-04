using System;
using System.IO;
using Altinn.Common.AccessToken.Authorization;
using Altinn.Common.AccessToken.KeyProvider;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Dependency injection extensions for access token.
/// </summary>
public static class AltinnAccessTokenDependencyInjectionExtensions
{
    /// <summary>
    /// Adds the Altinn token handler to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The current configuration.</param>
    /// <param name="environment">The current environment.</param>
    /// <returns><paramref name="services"/>.</returns>
    public static IServiceCollection AddAltinnTokenHandler(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        AddAltinnTokenValidator(services, configuration, environment);

        services.TryAddSingleton<IAuthorizationHandler, AccessTokenHandler>();
        return services;
    }

    /// <summary>
    /// Adds the Altinn token validator to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The current configuration.</param>
    /// <param name="environment">The current environment.</param>
    /// <returns><paramref name="services"/>.</returns>
    public static IServiceCollection AddAltinnTokenValidator(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        if (services.Contains(Marker.ServiceDescriptor))
        {
            return services;
        }

        services.Add(Marker.ServiceDescriptor);

        var enableLocalCerts = configuration.GetValue("Local:Enable", defaultValue: false);
        var localCertsPath = configuration.GetValue<string>("Local:CertificatesDirectory");
        var clientId = configuration.GetValue<string>("ClientId");
        var tenantId = configuration.GetValue<string>("TenantId");
        var clientSecret = configuration.GetValue<string>("ClientSecret");
        var keyVaultUri = configuration.GetValue<string>("VaultUri") ?? configuration.GetValue<string>("SecretUri");
        var enableEnvironmentCredential = configuration.GetValue("Credentials:Environment:Enable", defaultValue: false);
        var enableWorkloadIdentityCredential = configuration.GetValue("Credentials:WorkloadIdentity:Enable", defaultValue: false);
        var enableManagedIdentityCredential = configuration.GetValue("Credentials:ManagedIdentity:Enable", defaultValue: false);

        if (environment.IsDevelopment() && enableLocalCerts)
        {
            localCertsPath ??= Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Altinn", "DevCertificates");

            services.AddOptions<LocalCertificatePublicSigningKeyProvider.Settings>()
                .Configure(opts => opts.CertificatesDirectory = localCertsPath)
                .ValidateDataAnnotations();
            services.TryAddSingleton<LocalCertificatePublicSigningKeyProvider>();
            services.TryAddSingleton<IPublicSigningKeyProvider>(s => s.GetRequiredService<LocalCertificatePublicSigningKeyProvider>());
            services.TryAddSingleton<ISigningCredentialsProvider>(s => s.GetRequiredService<LocalCertificatePublicSigningKeyProvider>());

            return services;
        }
        
        if (Uri.TryCreate(keyVaultUri, UriKind.Absolute, out var uri))
        {
            services.AddOptions<AzureTokenCredentialProvider.Settings>()
                .Configure(opts =>
                {
                    opts.ClientId = clientId;
                    opts.TenantId = tenantId;
                    opts.ClientSecret = clientSecret;
                    opts.EnableEnvironmentCredential = enableEnvironmentCredential;
                    opts.EnableWorkloadIdentityCredential = enableWorkloadIdentityCredential;
                    opts.EnableManagedIdentityCredential = enableManagedIdentityCredential;
                })
                .ValidateDataAnnotations();

            services.TryAddSingleton<AzureTokenCredentialProvider>();
            services.TryAddKeyedSingleton(serviceKey: typeof(IPublicSigningKeyProvider), (services, _key) =>
            {
                var provider = services.GetRequiredService<AzureTokenCredentialProvider>();
                return new SecretClient(uri, provider.GetTokenCredential());
            });
        }

        services.TryAddSingleton<IPublicSigningKeyProvider, AzureKeyVaultPublicSigningKeyProvider>();
        return services;
    }

    private sealed class Marker
    {
        public static readonly ServiceDescriptor ServiceDescriptor = ServiceDescriptor.Singleton<Marker, Marker>();
    }
}
