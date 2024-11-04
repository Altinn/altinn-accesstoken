using Altinn.Common.AccessToken.KeyProvider;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Options;

namespace Altinn.AccessToken.Tests;

public class DependencyInjectionExtensionsTests
{
    [Fact]
    public void EmptyConfiguration_EnablesAzureKeyVaultPublicSigningKeyProvider()
    {
        var config = new ConfigurationBuilder().Build();
        var services = new ServiceCollection();
        var env = new HostingEnvironment { };

        services.AddSingleton<IHostEnvironment>(env);
        services.AddAltinnTokenHandler(config, env);

        var descriptor = services.Should().ContainSingle(s => s.ServiceType == typeof(IPublicSigningKeyProvider)).Which;
        descriptor.ImplementationType.Should().Be(typeof(AzureKeyVaultPublicSigningKeyProvider));
    }

    [Fact]
    public void LocalConfiguration_EnablesLocalCertificatePublicSigningKeyProvider_WithDefaultDir()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Local:Enable"] = "true",
            })
            .Build();

        var services = new ServiceCollection();
        var env = new HostingEnvironment { EnvironmentName = "Development" };
        services.AddSingleton<IHostEnvironment>(env);
        services.AddAltinnTokenHandler(config, env);

        using var di = services.BuildServiceProvider();
        var publicSigningKeyProvider = di.GetRequiredService<IPublicSigningKeyProvider>();
        publicSigningKeyProvider.Should().BeOfType<LocalCertificatePublicSigningKeyProvider>();

        var localSettings = di.GetRequiredService<IOptionsMonitor<LocalCertificatePublicSigningKeyProvider.Settings>>().CurrentValue;
        localSettings.CertificatesDirectory.Should().Be(Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Altinn", "DevCertificates"));
    }

    [Fact]
    public void LocalConfiguration_EnablesLocalCertificatePublicSigningKeyProvider_WithCustomDir()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Local:Enable"] = "true",
                ["Local:CertificatesDirectory"] = "/tmp/certs",
            })
            .Build();

        var services = new ServiceCollection();
        var env = new HostingEnvironment { EnvironmentName = "Development" };
        services.AddSingleton<IHostEnvironment>(env);
        services.AddAltinnTokenHandler(config, env);

        using var di = services.BuildServiceProvider();
        var publicSigningKeyProvider = di.GetRequiredService<IPublicSigningKeyProvider>();
        publicSigningKeyProvider.Should().BeOfType<LocalCertificatePublicSigningKeyProvider>();

        var localSettings = di.GetRequiredService<IOptionsMonitor<LocalCertificatePublicSigningKeyProvider.Settings>>().CurrentValue;
        localSettings.CertificatesDirectory.Should().Be("/tmp/certs");
    }

    [Fact]
    public void AzureConfiguration_SecretUri_EnablesAzureKeyVaultPublicSigningKeyProvider_And_SecretClient_WithDefaultCredentials()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SecretUri"] = "https://example.vault.azure.net/",
            })
            .Build();

        var services = new ServiceCollection();
        var env = new HostingEnvironment { EnvironmentName = "Development" };
        services.AddSingleton<IHostEnvironment>(env);
        services.AddLogging();
        services.AddAltinnTokenHandler(config, env);

        using var di = services.BuildServiceProvider();
        var credentialProvider = di.GetRequiredService<AzureTokenCredentialProvider>();
        var tokenCredential = credentialProvider.GetTokenCredential();
        tokenCredential.Should().BeOfType<DefaultAzureCredential>();

        var secretClient = di.GetRequiredKeyedService<SecretClient>(typeof(IPublicSigningKeyProvider));
        secretClient.VaultUri.Should().Be(new Uri("https://example.vault.azure.net/"));
    }

    [Fact]
    public void AzureConfiguration_VaultUri_EnablesAzureKeyVaultPublicSigningKeyProvider_And_SecretClient_WithDefaultCredentials()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VaultUri"] = "https://example.vault.azure.net/",
            })
            .Build();

        var services = new ServiceCollection();
        var env = new HostingEnvironment { EnvironmentName = "Development" };
        services.AddSingleton<IHostEnvironment>(env);
        services.AddLogging();
        services.AddAltinnTokenHandler(config, env);

        using var di = services.BuildServiceProvider();
        var credentialProvider = di.GetRequiredService<AzureTokenCredentialProvider>();
        var tokenCredential = credentialProvider.GetTokenCredential();
        tokenCredential.Should().BeOfType<DefaultAzureCredential>();

        var secretClient = di.GetRequiredKeyedService<SecretClient>(typeof(IPublicSigningKeyProvider));
        secretClient.VaultUri.Should().Be(new Uri("https://example.vault.azure.net/"));
    }
}
