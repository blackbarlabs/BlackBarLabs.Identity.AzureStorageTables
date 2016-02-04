using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace BlackBarLabs.Identity.AzureStorageTables.Tests
{
    [TestClass]
    public class RegistrationTests
    {
        [TestMethod]
        public async Task Post()
        {
            // Arrange
            AuthController controller = new AuthController();
            var authPost = new AuthPost()
            {
                Password = "Password",
                AuthIdentity = "Admin"
            };

            // Act
            var httpRequest = new HttpRequestMessage(HttpMethod.Post, "http://example.com");
            httpRequest.SetConfiguration(new HttpConfiguration());
            authPost.Request = httpRequest;
            await authPost.ExecuteAsync(CancellationToken.None);

            // Assert
        }
    }
}
