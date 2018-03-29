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
    public class HomeController : Controller
    {

        public ActionResult Index()
        {
            try
            { 

                return View();
            }
            catch(Exception ex)
            {
                //com.bfcusa.Log.Exception(ex);
                return RedirectToAction("Error");
            }
        }

        public ActionResult Error()
        {
            return View();
        }


        private string CreateSession(string BusinessKey, string IPAddress)
        {
            string SessionID = Guid.NewGuid().ToString();
            try
            {
                XmlDocument xdSession = new XmlDocument();
                string tranId = Guid.NewGuid().ToString();
                string createTokenXml = string.Format("<SessionXml><Authorization xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><TransactionId>{0}</TransactionId><ReturnUrl>Confirmation</ReturnUrl><AuthAmount>1.00</AuthAmount><KeyValue><Key>IPAddress</Key><Value>{1}</Value></KeyValue></Authorization></SessionXml>", tranId, IPAddress);
                xdSession.LoadXml(createTokenXml);
                XmlNode SessionXml = xdSession.DocumentElement;


                string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
                if (String.IsNullOrEmpty(connectionString))
                    throw new Exception("HistoriaConnectionString is required in the web.config");

                using (System.Data.SqlClient.SqlCommand cmd = new SqlConnection(connectionString).CreateCommand())
                {
                    //Get a list of Merchants with Permission & 4 = 4
                    cmd.CommandText = "Session_CreateSession";
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    cmd.Parameters.Add("@SessionId", System.Data.SqlDbType.UniqueIdentifier).Value = Guid.Parse(SessionID);
                    cmd.Parameters.Add("@BusinessKey", System.Data.SqlDbType.NVarChar, 50).Value = BusinessKey;
                    cmd.Parameters.Add("@SessionXml", System.Data.SqlDbType.Xml).Value = xdSession.OuterXml;
                    if (cmd.Connection.State != System.Data.ConnectionState.Open)
                        cmd.Connection.Open();

                    cmd.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Historia.Framework.Utility.Log(ex.ToString());
            }
            return SessionID;
        }

        private void UpdateSessionData(Guid SessionID, XmlNode xmlSession)
        {
            try
            {

                string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
                if (String.IsNullOrEmpty(connectionString))
                    throw new Exception("HistoriaConnectionString is required in the web.config");

                using (System.Data.SqlClient.SqlCommand sqlUpdateSession = new SqlConnection(connectionString).CreateCommand())
                {

                    sqlUpdateSession.CommandText = "Session_UpdateSession";
                    sqlUpdateSession.CommandType = CommandType.StoredProcedure;
                    sqlUpdateSession.Parameters.Add("@SessionID", SqlDbType.UniqueIdentifier).Value = SessionID;
                    sqlUpdateSession.Parameters.Add("@SessionXml", SqlDbType.Xml).Value = xmlSession.OuterXml;
                    if (sqlUpdateSession.Connection.State != System.Data.ConnectionState.Open)
                        sqlUpdateSession.Connection.Open();
                    sqlUpdateSession.ExecuteNonQuery();
                }
            }
            catch (SqlException x)
            {
                Historia.Framework.Utility.Log(x.ToString());
                throw;
            }                        
        }
    }
    
}
