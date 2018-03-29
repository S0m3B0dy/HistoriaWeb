using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Historia.Resources.ResourceProviders
{
    public interface ILocalizationResourceProvider
    {
        string GetString(string cultureName, string key);

        string GetString(string key);

        IHtmlString GetHtmlString(string cultureName, string key);

        IHtmlString GetHtmlString(string key);

        bool SetString(string key, string value);

        bool SetString(string cultureName, string key, string value, string resourceSet);

        bool SetBinary(string key, byte[] value);

        bool SetBinary(string cultureName, string key, byte[] value, string resourceSet);
    }
}
