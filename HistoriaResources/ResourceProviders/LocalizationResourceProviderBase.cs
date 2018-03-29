using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace Historia.Resources.ResourceProviders
{
    public abstract class LocalizationResourceProviderBase : ILocalizationResourceProvider
    {
        protected LocalizationResourceProviderBase()
        {
        }       

        public string GetString(string cultureName, string key)
        {
            return OnGetString(cultureName, key);
        }

        public string GetString(string key)
        {
            // find the localized result only if the key is not null
            var result = string.IsNullOrWhiteSpace(key) ? null : GetString(LocalizationResourceProvider.CultureName, key);
            // return the original key if didn't find the localized result
            return string.IsNullOrWhiteSpace(result) ? key : result;
        }

        public bool SetString(string cultureName, string key, string value, string resourceSet)
        {
            return OnSetString(cultureName, key, value, resourceSet);
        }

        public bool SetString(string key, string value)
        {
            return OnSetString(LocalizationResourceProvider.CultureName, key, value, string.Empty);
        }

        public bool SetBinary(string cultureName, string key, byte[] value, string resourceSet)
        {
            return OnSetBinary(cultureName, key, value, resourceSet);
        }

        public bool SetBinary(string key, byte[] value)
        {
            return OnSetBinary(LocalizationResourceProvider.CultureName, key, value, string.Empty);
        }

        public IHtmlString GetHtmlString(string cultureName, string key)
        {
            return MvcHtmlString.Create(GetString(cultureName, key));
        }

        public IHtmlString GetHtmlString(string key)
        {
            return MvcHtmlString.Create(GetString(key));
        }

        protected abstract string OnGetString(string cultureName, string key);
        protected abstract byte[] OnGetBinary(string cultureName, string key);

        protected abstract bool OnSetString(string cultureName, string key, string value, string resourceSet);

        protected abstract bool OnSetBinary(string cultureName, string key, byte[] value, string resourceSet);
    }
}
