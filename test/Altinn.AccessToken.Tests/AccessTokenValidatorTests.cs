using Altinn.Common.AccessToken.Services;

namespace Altinn.AccessToken.Tests
{
    public class AccessTokenValidatorTests
    {
        [Fact]
        public async Task AlwaysFalse_ThisTestDoesntTestAnything()
        {
            // Arrange
            var target = new AccessTokenValidator(null, null);

            // Act
            bool result = await target.Validate("notatoken");

            // Arrange
            Assert.False(result);
        }
    }
}
