using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Xml;
using IdentityTests.Properties;
using Microsoft.IdentityModel.Extensions;
using NUnit.Framework;

namespace IdentityTests
{
	[TestFixture]
	public class ReadTokens
	{
		private const string AZURE_TOKEN =
				@"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ing0Nzh4eU9wbHNNMUg3TlhrN1N4MTd4MXVwYyIsImtpZCI6Ing0Nzh4eU9wbHNNMUg3TlhrN1N4MTd4MXVwYyJ9.eyJhdWQiOiIzZTQxZWYwZS1iOTQ3LTRkNDItYWM0ZS1hOTQ5MGI5YjU3NGMiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9hNDFjOTA0Zi0zYzg0LTRmZGUtOTZhMC05YWFiZjFkY2ViYWYvIiwiaWF0IjoxNTEyNzI5NDk0LCJuYmYiOjE1MTI3Mjk0OTQsImV4cCI6MTUxMjczMzM5NCwiYWlvIjoiQVNRQTIvOEdBQUFBSTk5Y2NlUmk2L0dKM0tMMEtQRjZsWXhGRi9vNjJ6N0V0cmF6OWtNUXZBdz0iLCJhbXIiOlsicHdkIl0sImNfaGFzaCI6Imkxbk8yNUJXWVhWcWtyS3BzSk5YZ2ciLCJpcGFkZHIiOiI3OS4xMzMuNzUuNTgiLCJuYW1lIjoiV0lGIFRlc3QgVXNlciIsIm5vbmNlIjoiNjM2NDgzMjY1NzM4NDU1NjgyLk1UZzBNbVZoWTJVdE9EaGlNUzAwT0dVM0xUaG1abVl0WlRoa01UWTNaRFZsWm1ObVptVTRaakF6WkRjdE9ETmpNaTAwWXpBMExUbGxNalV0WXpWaE16UmxORFk0WVdObCIsIm9pZCI6ImM4ZDc4ODNlLTU0ZGMtNDhlOC1hOGFiLTg1MzU3ZDI1ODEyYSIsInN1YiI6ImV0R2lFam9GTC10ZURFSG13NlNzaDd0d2FoWDhESFlKT1FUQmRDa3phMFUiLCJ0aWQiOiJhNDFjOTA0Zi0zYzg0LTRmZGUtOTZhMC05YWFiZjFkY2ViYWYiLCJ1bmlxdWVfbmFtZSI6IndpZnRlc3R1c2VyQHdpZmRlbW9kYy5vbm1pY3Jvc29mdC5jb20iLCJ1cG4iOiJ3aWZ0ZXN0dXNlckB3aWZkZW1vZGMub25taWNyb3NvZnQuY29tIiwidXRpIjoiVDRlc3ZkUnhHVVc5Z3NPNUU5UVFBQSIsInZlciI6IjEuMCJ9.";

		private void PrintIdentity(ClaimsIdentity identity)
		{
			foreach (var claim in identity.Claims)
			{
				Console.WriteLine($@"{claim.Type} : {claim.Value}");
			}
		}

		private ClaimsPrincipal GetPrincipal(string tokenString)
		{
			var tokenHandlerCollection = new SecurityTokenHandlerCollection();
			tokenHandlerCollection.AddOrReplace(new JwtSecurityTokenHandler());
			tokenHandlerCollection.AddOrReplace(new SamlSecurityTokenHandler());

			var principal = tokenHandlerCollection.ValidateToken(tokenString,
				new TokenValidationParameters
				{
					RequireSignedTokens = false,
					ValidateLifetime = false,
					ValidateAudience = false,
					ValidateIssuer = false,
					ValidateActor = false,
					ValidateIssuerSigningKey = false
				}, out _);

			return principal;
		}

		[Test]
		public void ReadAzureToken()
		{
			var principal = GetPrincipal(AZURE_TOKEN);

			var identity = principal.Identities.First();

			PrintIdentity(identity);
		}

		const string CERTIFICATE_THUMBPRINT = "413e29a283887620ef2c3b0f18c94cd1da7f488d";
		const string ISSUER_NAME = "EPAM ADFS";

		[Test]
		public void ReadEpamSignedSamlToken()
		{
			var tokenHandler = new SamlSecurityTokenHandler();
			var issuerRegistry = new ConfigurationBasedIssuerNameRegistry();
			issuerRegistry.AddTrustedIssuer(CERTIFICATE_THUMBPRINT,
				ISSUER_NAME);

			tokenHandler.Configuration = new SecurityTokenHandlerConfiguration()
			{
				AudienceRestriction = new AudienceRestriction(AudienceUriMode.Never),
				IssuerNameRegistry = issuerRegistry,
				MaxClockSkew = TimeSpan.MaxValue
			};

			var xmlReader = XmlReader.Create(new StringReader(Resource.EpamToken));
			var token = tokenHandler.ReadToken(xmlReader, new NamedKeyIssuerTokenResolver()) as SamlSecurityToken;

			var identity = tokenHandler.ValidateToken(token).First();

			PrintIdentity(identity);
		}
	}
}
