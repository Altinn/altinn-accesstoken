using System.Reflection;
using System.Security.Claims;

using Altinn.AccessToken.Tests.Mocks;
using Altinn.Common.AccessToken;
using Altinn.Common.AccessToken.Configuration;

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
        public async Task HandleRequirementAsync_MultipleAccessTokens_HasNotSucceeded()
        {
            // Arrange
            Mock<IHttpContextAccessor> httpContextMock = new();
            var context = new DefaultHttpContext();
            context.Request.Headers["PlatformAccessToken"] = new StringValues(new string[] { "randomunreadabletoken", "randomtoken2" });
            httpContextMock.Setup(c => c.HttpContext).Returns(context);

            var (TestClass, TestMethod, AuthzContext, AuthzRequirement) = GetTestClassAndMethod(httpContextMock);
            // Act
            await (Task)TestMethod.Invoke(TestClass, new object[] { AuthzContext, AuthzRequirement });

            // Assert
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
            ) GetTestClassAndMethod(Mock<IHttpContextAccessor>? httpContextMock = null)
        {   // Arrange

            if (httpContextMock is null)
            {
                httpContextMock = new();
                var context = new DefaultHttpContext();
                context.Request.Headers["PlatformAccessToken"] = GetToken();
                httpContextMock.Setup(c => c.HttpContext).Returns(context);
            }

            var loggerMock = new Mock<ILogger<AccessTokenHandlerBase<AccessTokenRequirement>>>();

            var testClass = new AccessTokenHandlerBase<AccessTokenRequirement>(
                httpContextMock.Object,
                loggerMock.Object,
                Options.Create(new AccessTokenSettings()),
                new SigningKeyResolverMock());

            var testMethod = testClass.GetType().GetMethod("HandleRequirementAsync", BindingFlags.NonPublic | BindingFlags.Instance);

            var requirement = new AccessTokenRequirement();
            var authzContext = new AuthorizationHandlerContext(new List<IAuthorizationRequirement> { requirement }, new ClaimsPrincipal(), null);


            return (testClass, testMethod, authzContext, requirement);
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
