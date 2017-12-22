using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using NUnit.Framework;

namespace IdentityTests
{
	[TestFixture]
	public class WriteAndPrintTokens
	{
		private readonly Saml2SecurityTokenHandler _saml2SecurityTokenHandler = new Saml2SecurityTokenHandler();
		private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

		private const string CERT_THUMBPRINT = "AC57D46308FF5F9AD01ABB43B0C1A562EFC001EB";

		private ClaimsIdentity CreateClaimsIdentity()
		{
			var claims = new[]
			{
				new Claim(ClaimTypes.Name, "Dmitrii Chernov"),
				new Claim(ClaimTypes.Country, "Russia"),
				new Claim(ClaimTypes.Email, "Dmitrii_Chernov1@epam.com"),
				new Claim("http://epam.com/claims/upsaId", "1"),
				new Claim("http://epam.com/claims/unit", "4"),
				new Claim("http://epam.com/claims/pool", ".NET")
			};

			var identity = new ClaimsIdentity(claims);

			return identity;
		}

		private SecurityToken CreateToken(SecurityTokenHandler handler, ClaimsIdentity identity, SigningCredentials signingCredentials = null, EncryptingCredentials encryptingCredentials = null)
		{
			var token = handler.CreateToken(new SecurityTokenDescriptor
			{
				TokenIssuerName = "Dmitrii Chernov",
				Subject = identity,
				SigningCredentials = signingCredentials,
				EncryptingCredentials = encryptingCredentials
			});

			return token;
		}

		private void PrintSaml2Token(Saml2SecurityToken token)
		{
			var sb = new StringBuilder();
			var xmlWriter = XmlWriter.Create(sb, new XmlWriterSettings{Indent = true});

			_saml2SecurityTokenHandler.WriteToken(xmlWriter, token);
			xmlWriter.Close();

			Console.WriteLine(sb.ToString());
		}

		private void PrintJwtToken(JwtSecurityToken token)
		{
			var serializedToken = _jwtSecurityTokenHandler.WriteToken(token);

			Console.WriteLine(serializedToken);
			Console.WriteLine();

			serializedToken
				.Split('.')
				.Select(Base64UrlEncoder.Decode)
				.ToList()
				.ForEach(Console.WriteLine);
		}

		private X509Certificate2 GetCertificate()
		{
			using (var store = new X509Store())
			{
				store.Open(OpenFlags.ReadOnly);
				var cert = store.Certificates.Find(X509FindType.FindByThumbprint, CERT_THUMBPRINT, false)[0];

				return cert;
			}
		}

		private EncryptingCredentials GetEncryptingCredentials()
		{
			var tripleDes = TripleDES.Create();
			tripleDes.GenerateKey();

			var encryptingKey = tripleDes.Key;

			var encryptingCredentials = new EncryptingCredentials
			{
				SecurityKey = new InMemorySymmetricSecurityKey(encryptingKey),
				Algorithm = SecurityAlgorithms.TripleDesEncryption,
				SecurityKeyIdentifier = new SecurityKeyIdentifier(new EncryptedKeyIdentifierClause(encryptingKey, SecurityAlgorithms.TripleDesEncryption))
			};

			return encryptingCredentials;
		}

		private SigningCredentials GetSigningCredentials()
		{
			var signingCredentials = new X509SigningCredentials(GetCertificate());

			return signingCredentials;
		}

		[Test]
		public void PrintClaimsFromIdentity()
		{
			var identity = CreateClaimsIdentity();
			var principal = new ClaimsPrincipal(identity);
			ClaimsPrincipal.ClaimsPrincipalSelector = () => principal;
			ClaimsPrincipal.Current.Claims.ToList().ForEach(c => Console.WriteLine($@"{c.Type} : {c.Value}"));
		}

		[Test]
		public void PrintSaml2Token()
		{
			var token = CreateToken(_saml2SecurityTokenHandler, CreateClaimsIdentity()) as Saml2SecurityToken;
			PrintSaml2Token(token);
		}

		[Test]
		public void PrintJwtToken()
		{
			var token = CreateToken(_jwtSecurityTokenHandler, CreateClaimsIdentity()) as JwtSecurityToken;
			PrintJwtToken(token);
		}

		[Test]
		public void PrintSaml2SignedToken()
		{
			var token = CreateToken(_saml2SecurityTokenHandler, CreateClaimsIdentity(), GetSigningCredentials()) as Saml2SecurityToken;
			PrintSaml2Token(token);
		}

		[Test]
		public void PrintJwtSignedToken()
		{
			var token = CreateToken(_jwtSecurityTokenHandler, CreateClaimsIdentity(), GetSigningCredentials()) as JwtSecurityToken;
			PrintJwtToken(token);
		}

		[Test]
		public void PrintSaml2SignedEncryptedToken()
		{
			var token = CreateToken(_saml2SecurityTokenHandler, CreateClaimsIdentity(), GetSigningCredentials(), GetEncryptingCredentials()) as Saml2SecurityToken;
			PrintSaml2Token(token);
		}

		[Test]
		public void PrintJwtSignedEncryptedToken()
		{
			var token = CreateToken(_jwtSecurityTokenHandler, CreateClaimsIdentity(), GetSigningCredentials(), GetEncryptingCredentials()) as JwtSecurityToken;
			PrintJwtToken(token);
		}
	}
}
