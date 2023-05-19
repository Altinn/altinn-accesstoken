using System.Security.Claims;

using Altinn.AccessToken.Tests.Mock;

using Altinn.Common.AccessToken;
using Altinn.Common.AccessToken.Configuration;
using Altinn.Common.AccessToken.Services;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Altinn.AccessToken.Tests
{
    public class AccessTokenHandlerTests
    {
        private readonly Mock<IHttpContextAccessor> _httpContextAccessor = new();
        private readonly Mock<ILogger<AccessTokenHandler>> _logger = new();
        private readonly Mock<IOptions<AccessTokenSettings>> _options = new();
        private readonly PublicSigningKeyProviderMock _signingKeysResolver = new();

        private readonly List<IAuthorizationRequirement> _reqs = new List<IAuthorizationRequirement>
        {
            new AccessTokenRequirement()
        };

        [Fact]
        public async Task HandleAsyncTest_TokenMissingAndVerificationDisabled_ResultSuccessful()
        {
            // Arrange
            AccessTokenSettings accessTokenSettings = new() { DisableAccessTokenVerification = true };
            _options.Setup(s => s.Value).Returns(accessTokenSettings);

            _httpContextAccessor.Setup(s => s.HttpContext).Returns(new DefaultHttpContext());

            var context = new AuthorizationHandlerContext(_reqs, PrincipalUtil.CreateClaimsPrincipal(), null);

            var target = new AccessTokenHandler(
                _httpContextAccessor.Object, _logger.Object, _options.Object, _signingKeysResolver);

            // Act
            await target.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
        }

        [Fact]
        public async Task HandleAsyncTest_TokenMissingAndVerificationEnabled_ResultNotSuccessful()
        {
            // Arrange
            AccessTokenSettings accessTokenSettings = new();
            _options.Setup(s => s.Value).Returns(accessTokenSettings);

            _httpContextAccessor.Setup(s => s.HttpContext).Returns(new DefaultHttpContext());

            var context = new AuthorizationHandlerContext(_reqs, PrincipalUtil.CreateClaimsPrincipal(), null);

            var target = new AccessTokenHandler(
                _httpContextAccessor.Object, _logger.Object, _options.Object, _signingKeysResolver);

            // Act
            await target.HandleAsync(context);

            // Assert
            Assert.False(context.HasSucceeded);
        }

        [Fact]
        public async Task HandleAsyncTest_TokenNotValidAndVerificationEnabled_ResultNotSuccessful()
        {
            // Arrange
            AccessTokenSettings accessTokenSettings = new();
            _options.Setup(s => s.Value).Returns(accessTokenSettings);

            DefaultHttpContext httpContext = new DefaultHttpContext();
            httpContext.Request.Headers.Add("PlatformAccessToken", "notatoken");

            _httpContextAccessor.Setup(s => s.HttpContext).Returns(httpContext);

            var context = new AuthorizationHandlerContext(_reqs, PrincipalUtil.CreateClaimsPrincipal(), null);

            var target = new AccessTokenHandler(
                _httpContextAccessor.Object, _logger.Object, _options.Object, _signingKeysResolver);

            // Act
            await target.HandleAsync(context);

            // Assert
            Assert.False(context.HasSucceeded);
        }

        [Fact]
        public async Task HandleAsyncTest_TokenExpiredAndVerificationEnabled_ResultSuccessful()
        {
            // Arrange
            AccessTokenSettings accessTokenSettings = new();
            _options.Setup(s => s.Value).Returns(accessTokenSettings);

            ClaimsPrincipal principal = PrincipalUtil.CreateClaimsPrincipal();
            string accessToken = AccessTokenCreator.GenerateToken(principal, new TimeSpan(0, 0, -5), "ttd");

            DefaultHttpContext httpContext = new DefaultHttpContext();
            httpContext.Request.Headers.Add("PlatformAccessToken", accessToken);

            _httpContextAccessor.Setup(s => s.HttpContext).Returns(httpContext);

            var context = new AuthorizationHandlerContext(_reqs, PrincipalUtil.CreateClaimsPrincipal(), null);

            var target = new AccessTokenHandler(
                _httpContextAccessor.Object, _logger.Object, _options.Object, _signingKeysResolver);

            // Act
            await target.HandleAsync(context);

            // Assert
            Assert.False(context.HasSucceeded);
        }

        [Fact]
        public async Task HandleAsyncTest_TokenValidAndVerificationEnabled_ResultSuccessful()
        {
            // Arrange
            AccessTokenSettings accessTokenSettings = new();
            _options.Setup(s => s.Value).Returns(accessTokenSettings);

            ClaimsPrincipal principal = PrincipalUtil.CreateClaimsPrincipal();
            string accessToken = AccessTokenCreator.GenerateToken(principal, new TimeSpan(0, 0, 5), "ttd");

            DefaultHttpContext httpContext = new DefaultHttpContext();
            httpContext.Request.Headers.Add("PlatformAccessToken", accessToken);

            _httpContextAccessor.Setup(s => s.HttpContext).Returns(httpContext);

            var context = new AuthorizationHandlerContext(_reqs, PrincipalUtil.CreateClaimsPrincipal(), null);

            var target = new AccessTokenHandler(
                _httpContextAccessor.Object, _logger.Object, _options.Object, _signingKeysResolver);

            // Act
            await target.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
            Assert.True(httpContext.Items.ContainsKey("accesstokencontextid"));
        }

        [Fact]
        public async Task HandleAsyncTest_ErrorObtainingKeysAndVerificationEnabled_ResultNotSuccessful()
        {
            // Arrange
            AccessTokenSettings accessTokenSettings = new();
            _options.Setup(s => s.Value).Returns(accessTokenSettings);

            ClaimsPrincipal principal = PrincipalUtil.CreateClaimsPrincipal();
            string accessToken = AccessTokenCreator.GenerateToken(principal, new TimeSpan(0, 0, 5), "ttd");

            DefaultHttpContext httpContext = new DefaultHttpContext();
            httpContext.Request.Headers.Add("PlatformAccessToken", accessToken);

            _httpContextAccessor.Setup(s => s.HttpContext).Returns(httpContext);

            var context = new AuthorizationHandlerContext(_reqs, PrincipalUtil.CreateClaimsPrincipal(), null);

            var publicKeyProvider = new Mock<IPublicSigningKeyProvider>();
            publicKeyProvider.Setup(s => s.GetSigningKeys(It.IsAny<string>())).ThrowsAsync(new Exception("omg!"));

            var target = new AccessTokenHandler(
                _httpContextAccessor.Object, _logger.Object, _options.Object, publicKeyProvider.Object);

            // Act
            await target.HandleAsync(context);

            // Assert
            Assert.False(context.HasSucceeded);
        }

        [Fact]
        public async Task HandleAsyncTest_ErrorObtainingKeysAndVerificationDisabled_ResultSuccessful()
        {
            // Arrange
            AccessTokenSettings accessTokenSettings = new() { DisableAccessTokenVerification = true };
            _options.Setup(s => s.Value).Returns(accessTokenSettings);

            ClaimsPrincipal principal = PrincipalUtil.CreateClaimsPrincipal();
            string accessToken = AccessTokenCreator.GenerateToken(principal, new TimeSpan(0, 0, 5), "ttd");

            DefaultHttpContext httpContext = new DefaultHttpContext();
            httpContext.Request.Headers.Add("PlatformAccessToken", accessToken);

            _httpContextAccessor.Setup(s => s.HttpContext).Returns(httpContext);

            var context = new AuthorizationHandlerContext(_reqs, PrincipalUtil.CreateClaimsPrincipal(), null);

            var publicKeyProvider = new Mock<IPublicSigningKeyProvider>();
            publicKeyProvider.Setup(s => s.GetSigningKeys(It.IsAny<string>())).ThrowsAsync(new Exception("omg!"));

            var target = new AccessTokenHandler(
                _httpContextAccessor.Object, _logger.Object, _options.Object, publicKeyProvider.Object);

            // Act
            await target.HandleAsync(context);

            // Assert
            Assert.True(context.HasSucceeded);
        }
    }
}
