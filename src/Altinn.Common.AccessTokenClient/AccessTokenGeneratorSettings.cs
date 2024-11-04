namespace Altinn.Common.AccessTokenClient;

/// <summary>
/// Settings for access token generation.
/// </summary>
public class AccessTokenGeneratorSettings
{
    /// <summary>
    /// The lifetime for a token
    /// </summary>
    public int TokenLifetimeInSeconds { get; set; } = 300;

    /// <summary>
    /// Specify the number of seconds to add (or subtract) to the current time when determining
    /// when the access token should be considered valid
    /// </summary>
    public int ValidFromAdjustmentSeconds { get; set; } = -5;
}
