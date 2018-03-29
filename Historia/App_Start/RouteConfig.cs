using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace Historia.App_Start
{
    public class GuidConstraint : IRouteConstraint
    {
        public bool Match(HttpContextBase httpContext, Route route, string parameterName, RouteValueDictionary values, RouteDirection routeDirection)
        {
            var value = values[parameterName] as string;
            Guid guid;
            if (!string.IsNullOrEmpty(value) && Guid.TryParse(value, out guid))
            {
                return true;
            }
            return false;
        }
    }

    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");

            //Require the session ID; will create a route constraint that the Session ID is a GUID from our system
            routes.MapRoute(
                name: "HistoriaPage",
                url: "{controller}/{action}/{SessionID}",
                defaults: new { controller = "Payment", action = "CTS"},
                constraints: new { SessionID = new GuidConstraint() }
            );


            routes.MapRoute(
                name: "Default",
                url: "{controller}/{action}/{id}",
                defaults: new { controller = "Account", action = "Login", id = UrlParameter.Optional }
            );
            
        }
    }
}