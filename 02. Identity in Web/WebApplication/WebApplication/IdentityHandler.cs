using System.Security.Claims;
using System.Web;

namespace WebApplication
{
	public class IdentityHandler : IHttpHandler
	{
		/// <summary>Enables processing of HTTP Web requests by a custom HttpHandler that implements the <see cref="T:System.Web.IHttpHandler" /> interface.</summary>
		/// <param name="context">An <see cref="T:System.Web.HttpContext" /> object that provides references to the intrinsic server objects (for example, Request, Response, Session, and Server) used to service HTTP requests. </param>
		public void ProcessRequest(HttpContext context)
		{
			var user = context.User;

			context.Response.Write($"Is authenticated: {user.Identity.IsAuthenticated}");
			context.Response.Write("</br>");
			context.Response.Write($"User: {user.Identity.Name}");

			var cIdentity = context.User.Identity as ClaimsIdentity;
			if (cIdentity != null)
			{
				context.Response.Write("<br/>");
				foreach (var c in cIdentity.Claims)
				{
					PrintClaim(context, c);
				}
			}
		}

		/// <summary>Gets a value indicating whether another request can use the <see cref="T:System.Web.IHttpHandler" /> instance.</summary>
		/// <returns>true if the <see cref="T:System.Web.IHttpHandler" /> instance is reusable; otherwise, false.</returns>
		public bool IsReusable => true;

		private void PrintClaim(HttpContext context, Claim claim)
		{
			context.Response.Write("<hr/>");
			context.Response.Write($"Issuer : {claim.Issuer}<br/>");
			context.Response.Write($"Type : {claim.Type}<br/>");
			context.Response.Write($"Value : {claim.Value}<br/>");
			//context.Response.Write("<br/>");
		}
	}
}