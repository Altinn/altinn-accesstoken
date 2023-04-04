#nullable disable

using System.Reflection;
using System.Security.Claims;

using Altinn.AccessToken.Tests.Mocks;
using Altinn.Common.AccessToken;
using Altinn.Common.AccessToken.Configuration;
using Altinn.Common.AccessToken.Services;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

using Moq;

namespace Altinn.AccessToken.Tests
{
    public class AccessTokenHandlerBaseTests
    {
        [Fact]
        public async Task HandleRequirementAsync_ValidAccessToken_HasSucceeded()
        {
            // Arrange
            var (TestClass, TestMethod, AuthzContext, AuthzRequirement) = GetTestClassAndMethod();

            // Act
            await (Task)TestMethod.Invoke(TestClass, new object[] { AuthzContext, AuthzRequirement });

            // Assert
            Assert.True(AuthzContext.HasSucceeded);
        }

        [Fact]
        public async Task HandleRequirementAsync_NoAccessTokenSettingAndVerificationDisables_HasSucceeded()
        {
            // Arrange
            Mock<IHttpContextAccessor> httpContextMock = new();
            var context = new DefaultHttpContext();
            httpContextMock.Setup(c => c.HttpContext).Returns(context);

            var accessTokenSettings = new AccessTokenSettings()
            {
                DisableAccessTokenVerification = true
            };

            var loggerMock = new Mock<ILogger<AccessTokenHandlerBase<AccessTokenRequirement>>>();

            var (TestClass, TestMethod, AuthzContext, AuthzRequirement) = GetTestClassAndMethod(httpContextMock, accessTokenSettings, loggerMock);

            // Act
            await (Task)TestMethod.Invoke(TestClass, new object[] { AuthzContext, AuthzRequirement });

            // Assert
            AssertLogMessage(LogLevel.Warning, "Token is missing and function is turned off", loggerMock);
            Assert.True(AuthzContext.HasSucceeded);
        }

        [Fact]
        public async Task HandleRequirementAsync_ValidateAccessTokenThrowsExceptions_HasNotSucceeded()
        {
            // Arrange
            Mock<ISigningKeysResolver> mockKeysResolver = new();
            mockKeysResolver.Setup(r => r.GetSigningKeys(It.IsAny<string>()))
                .ThrowsAsync(new Exception());

            var loggerMock = new Mock<ILogger<AccessTokenHandlerBase<AccessTokenRequirement>>>();

            var (TestClass, TestMethod, AuthzContext, AuthzRequirement) = GetTestClassAndMethod(loggerMock: loggerMock, signingKeysResolver: mockKeysResolver.Object);

            // Act
            await (Task)TestMethod.Invoke(TestClass, new object[] { AuthzContext, AuthzRequirement });

            // Assert
            AssertLogMessage(LogLevel.Warning, "Validation of Access Token Failed", loggerMock);
            Assert.False(AuthzContext.HasSucceeded);
        }

        [Fact]
        public async Task HandleRequirementAsync_MultipleAccessTokens_HasNotSucceeded()
        {
            // Arrange
            Mock<IHttpContextAccessor> httpContextMock = new();
            var context = new DefaultHttpContext();
            context.Request.Headers["PlatformAccessToken"] = new StringValues(new string[] { "randomunreadabletoken", "randomtoken2" });
            httpContextMock.Setup(c => c.HttpContext).Returns(context);

            var loggerMock = new Mock<ILogger<AccessTokenHandlerBase<AccessTokenRequirement>>>();

            var (TestClass, TestMethod, AuthzContext, AuthzRequirement) = GetTestClassAndMethod(httpContextMock, null, loggerMock);
            // Act
            await (Task)TestMethod.Invoke(TestClass, new object[] { AuthzContext, AuthzRequirement });

            // Assert
            AssertLogMessage(LogLevel.Warning, "Missing Access token", loggerMock);
            Assert.False(AuthzContext.HasSucceeded);
        }

        [Fact]
        public async Task HandleRequirementAsync_CannotReadAccessToken_HasNotSucceeded()
        {
            // Arrange
            Mock<IHttpContextAccessor> httpContextMock = new();
            var context = new DefaultHttpContext();
            context.Request.Headers["PlatformAccessToken"] = "randomunreadabletoken";
            httpContextMock.Setup(c => c.HttpContext).Returns(context);

            var (TestClass, TestMethod, AuthzContext, AuthzRequirement) = GetTestClassAndMethod(httpContextMock);

            // Act
            await (Task)TestMethod.Invoke(TestClass, new object[] { AuthzContext, AuthzRequirement });

            // Assert
            Assert.False(AuthzContext.HasSucceeded);
        }

        private static (
            AccessTokenHandlerBase<AccessTokenRequirement> TestClass,
            MethodInfo TestMethod,
            AuthorizationHandlerContext AuthzContext,
            IAuthorizationRequirement AuthzRequirement
            ) GetTestClassAndMethod(
            Mock<IHttpContextAccessor> httpContextMock = null,
            AccessTokenSettings accessTokenSettings = null,
            Mock<ILogger<AccessTokenHandlerBase<AccessTokenRequirement>>> loggerMock = null,
            ISigningKeysResolver signingKeysResolver = null)
        {
            if (httpContextMock is null)
            {
                httpContextMock = new();
                var context = new DefaultHttpContext();
                context.Request.Headers["PlatformAccessToken"] = GetToken();
                httpContextMock.Setup(c => c.HttpContext).Returns(context);
            }

            if (accessTokenSettings is null)
            {
                accessTokenSettings = new AccessTokenSettings();
            }

            if (loggerMock is null)
            {
                loggerMock = new Mock<ILogger<AccessTokenHandlerBase<AccessTokenRequirement>>>();
            }

            if (signingKeysResolver is null)
            {
                signingKeysResolver = new SigningKeyResolverMock();
            }

            var testClass = new AccessTokenHandlerBase<AccessTokenRequirement>(
              httpContextMock.Object,
              loggerMock.Object,
              Options.Create(accessTokenSettings),
             signingKeysResolver);

            var testMethod = testClass.GetType().GetMethod("HandleRequirementAsync", BindingFlags.NonPublic | BindingFlags.Instance);

            var requirement = new AccessTokenRequirement();
            var authzContext = new AuthorizationHandlerContext(new List<IAuthorizationRequirement> { requirement }, new ClaimsPrincipal(), null);

            return (testClass, testMethod, authzContext, requirement);
        }

        private static void AssertLogMessage(
            LogLevel logLevel,
            string expectedMessage,
            Mock<ILogger<AccessTokenHandlerBase<AccessTokenRequirement>>> loggerMock)
        {
            loggerMock.Verify(x => x.Log(
                logLevel,
                It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((v, t) => v.ToString() == expectedMessage),
                It.IsAny<Exception>(),
                (Func<It.IsAnyType, Exception, string>)It.IsAny<object>()),
                Times.Once);
        }

        private static string GetToken()
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim("urn:altinn:userId", "12345", ClaimValueTypes.String, "Altinn")
             };

            ClaimsIdentity identity = new ClaimsIdentity("mock");
            identity.AddClaims(claims);


            ClaimsPrincipal principal = new ClaimsPrincipal(identity);

            string token = JwtTokenMock.GenerateToken(principal, new TimeSpan(0, 1, 5));

            return token;
        }

    }
}
