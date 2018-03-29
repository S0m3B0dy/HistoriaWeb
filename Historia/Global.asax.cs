using Historia.App_Start;
using Historia.Resources;
using Historia.Resources.ResourceProviders;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace Historia
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            // register the localization routes
            // note: this must be invoked before the RouteConfig.RegisterRoutes
            //LocalizationConfig.RegisterRoutes(RouteTable.Routes);            
            // specify the localiztion resource provider (and culture name resolver)
            LocalizationConfig.RegisterResourceProvider(() => new LocalizationDbResourceProvider());
            // register the localizable model providers
            LocalizationConfig.RegisterModelProviders();

            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }
    }
}
