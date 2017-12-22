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
		}

		/// <summary>Gets a value indicating whether another request can use the <see cref="T:System.Web.IHttpHandler" /> instance.</summary>
		/// <returns>true if the <see cref="T:System.Web.IHttpHandler" /> instance is reusable; otherwise, false.</returns>
		public bool IsReusable => true;
	}
}