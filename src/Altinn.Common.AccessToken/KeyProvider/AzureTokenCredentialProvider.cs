using System;
using System.Collections.Generic;
using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Altinn.Common.AccessToken.KeyProvider;

/// <summary>
/// Provides an <see cref="TokenCredential"/> based on the configuration.
/// </summary>
internal partial class AzureTokenCredentialProvider
{
    private readonly ILogger<AzureTokenCredentialProvider> _logger;
    private readonly IOptionsMonitor<Settings> _options;
    private readonly IHostEnvironment _hostEnvironment;

    private TokenCredential? _credential;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureTokenCredentialProvider"/> class.
    /// </summary>
    public AzureTokenCredentialProvider(
        ILogger<AzureTokenCredentialProvider> logger,
        IOptionsMonitor<Settings> options,
        IHostEnvironment hostEnvironment)
    {
        _logger = logger;
        _options = options;
        _hostEnvironment = hostEnvironment;
    }

    /// <summary>
    /// Gets a (cached) <see cref="TokenCredential"/> based on the configuration.
    /// </summary>
    /// <returns>A <see cref="TokenCredential"/>.</returns>
    public TokenCredential GetTokenCredential()
        => _credential ??= CreateCredential();

    private TokenCredential CreateCredential()
    {
        var settings = _options.CurrentValue;

        List<TokenCredential> credentialList = [];

        if (!string.IsNullOrEmpty(settings.ClientId)
            && !string.IsNullOrEmpty(settings.TenantId)
            && !string.IsNullOrEmpty(settings.ClientSecret))
        {
            Log.ClientSecretCredentialsEnabled(_logger);
            credentialList.Add(new ClientSecretCredential(
                tenantId: settings.TenantId,
                clientId: settings.ClientId,
                clientSecret: settings.ClientSecret));
        }

        if (settings.EnableEnvironmentCredential)
        {
            Log.EnvironmentCredentialsEnabled(_logger);
            credentialList.Add(new EnvironmentCredential());
        }

        if (settings.EnableWorkloadIdentityCredential)
        {
            Log.WorkloadIdentityCredentialsEnabled(_logger);
            credentialList.Add(new WorkloadIdentityCredential());
        }

        if (settings.EnableManagedIdentityCredential)
        {
            Log.ManagedIdentityCredentialsEnabled(_logger);
            credentialList.Add(new ManagedIdentityCredential());
        }

        if (credentialList.Count == 0)
        {
            Log.NoCredentialsConfigured(_logger);
            
            if (_hostEnvironment.IsDevelopment())
            {
                Log.UsingDefaultCredentials(_logger);
                return new DefaultAzureCredential(includeInteractiveCredentials: true);
            }

            throw new NotSupportedException("No credentials configured");
        }

        return new ChainedTokenCredential([.. credentialList]);
    }

    /// <summary>
    /// Settings for <see cref="AzureTokenCredentialProvider"/>.
    /// </summary>
    internal sealed class Settings
    {
        /// <summary>
        /// Gets or sets the client ID.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the tenant ID.
        /// </summary>
        public string? TenantId { get; set; }

        /// <summary>
        /// Gets or sets the client secret.
        /// </summary>
        public string? ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to enable environment credentials.
        /// </summary>
        public bool EnableEnvironmentCredential { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to enable workload identity credentials.
        /// </summary>
        public bool EnableWorkloadIdentityCredential { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to enable managed identity credentials.
        /// </summary>
        public bool EnableManagedIdentityCredential { get; set; }
    }

    private static partial class Log
    {
        [LoggerMessage(0, LogLevel.Information, "Client secret credentials enabled")]
        public static partial void ClientSecretCredentialsEnabled(ILogger logger);

        [LoggerMessage(1, LogLevel.Information, "Environment credentials enabled")]
        public static partial void EnvironmentCredentialsEnabled(ILogger logger);

        [LoggerMessage(2, LogLevel.Information, "Workload identity credentials enabled")]
        public static partial void WorkloadIdentityCredentialsEnabled(ILogger logger);

        [LoggerMessage(3, LogLevel.Information, "Managed identity credentials enabled")]
        public static partial void ManagedIdentityCredentialsEnabled(ILogger logger);

        [LoggerMessage(4, LogLevel.Information, "No credentials configured")]
        public static partial void NoCredentialsConfigured(ILogger logger);

        [LoggerMessage(5, LogLevel.Warning, "Using default azure credentials")]
        public static partial void UsingDefaultCredentials(ILogger logger);
    }
}
