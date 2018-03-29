using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Mvc;
using System.Web.Security;
using System.Xml;
using Historia.Resources.ResourceProviders;
using Newtonsoft.Json;
using Historia.Models;
using Newtonsoft.Json.Linq;
using ICSharpCode.SharpZipLib.Zip;  //for ZIP processing
using ICSharpCode.SharpZipLib.Core; //for transferring a memory stream into the zip file
using OfficeOpenXml;        // for excel export; in the EPPlus library.
using OfficeOpenXml.Table;
using System.Web;
using System.Configuration;

namespace Payment.Controllers
{
    public class TestbedController : Controller
    {

        public ActionResult Index()
        {
            try
            { 

                return View();
            }
            catch(Exception ex)
            {
                Historia.Framework.Utility.Log(ex.ToString());
                //com.bfcusa.Log.Exception(ex);
                return RedirectToAction("Error");
            }
        }

        [HttpPost]
        public JsonResult RunRPCTest(string callDetails)
        {
            try
            {
                dynamic json = JObject.Parse(callDetails);

                HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(json.hostIPAddress.ToString());
                webRequest.Credentials = new NetworkCredential(json.userName.ToString(), json.password.ToString());
                /// important, otherwise the service can't desirialse your request properly
                webRequest.ContentType = "application/json-rpc";
                webRequest.Method = "POST";

                JObject jo = new JObject();
                jo.Add(new JProperty("jsonrpc", "1.0"));
                jo.Add(new JProperty("id", "1"));
                jo.Add(new JProperty("method", json.methodName.ToString()));
                // params is a collection values which the method requires..
                //if (json.parameters != null && json.parameters.Count == 0)
                {
                    jo.Add(new JProperty("params", new JArray()));
                }
                //else
                {
                    //JArray props = new JArray();
                    // add the props in the reverse order!
                    //for (int i = json.parameters.Keys.Count - 1; i >= 0; i--)
                    //{
                    //    props.Add(json.parameters.)
                    //}
                    //jo.Add(new JProperty("params", props));

                }

                // serialize json for the request
                string s = JsonConvert.SerializeObject(jo);
                byte[] byteArray = Encoding.UTF8.GetBytes(s);
                webRequest.ContentLength = byteArray.Length;
                Stream dataStream = webRequest.GetRequestStream();
                dataStream.Write(byteArray, 0, byteArray.Length);
                dataStream.Close();

                WebResponse webResponse = webRequest.GetResponse();
                
                StreamReader sr = new StreamReader(webResponse.GetResponseStream());


                return Json(new { success = true, responseText = sr.ReadToEnd() });
            }
            catch (Exception ex)
            {
                Historia.Framework.Utility.Log(ex.ToString());
                return Json(new { success = false, responseText = "Exception while running test: " + ex.ToString() });
            }
        }


        public ActionResult Error()
        {
            return View();
        }
    }    
}
