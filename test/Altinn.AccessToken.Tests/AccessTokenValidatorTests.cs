using Altinn.Common.AccessToken.Services;
using Microsoft.Extensions.Logging;

namespace Altinn.AccessToken.Tests;

public class AccessTokenValidatorTests
{
    [Fact]
    public async Task Validate_InputIsNotValidatable_ReturnsFalse()
    {
        // Arrange
        Mock<IPublicSigningKeyProvider> signingKeyProviderMock = new Mock<IPublicSigningKeyProvider>();
        Mock<ILogger<AccessTokenValidator>> loggerMock = new Mock<ILogger<AccessTokenValidator>>();

        var target = new AccessTokenValidator(signingKeyProviderMock.Object, loggerMock.Object);

        // Act
        bool result = await target.Validate("notatoken");

        // Arrange
        Assert.False(result);
    }
}
