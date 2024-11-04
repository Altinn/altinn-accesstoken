using Altinn.Common.AccessToken;
using Altinn.Common.AccessToken.KeyProvider;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Altinn.AccessToken.Tests;

public class AccessTokenValidatorTests
{
    [Fact]
    public async Task Validate_InputIsNotValidatable_ReturnsFalse()
    {
        // Arrange
        Mock<IPublicSigningKeyProvider> signingKeyProviderMock = new Mock<IPublicSigningKeyProvider>();
        Mock<ILogger<AccessTokenValidator>> loggerMock = new Mock<ILogger<AccessTokenValidator>>();

        var target = new AccessTokenValidator(signingKeyProviderMock.Object, NullLogger<AccessTokenValidator>.Instance);

        // Act
        bool result = await target.Validate("notatoken");

        // Arrange
        Assert.False(result);
    }
}
