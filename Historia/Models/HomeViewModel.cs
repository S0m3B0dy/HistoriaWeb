using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Web;

namespace Historia.Models
{
    public class HomeViewModel
    {

        public HomeViewModel()
        {

            string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new Exception("HistoriaConnectionString is required in the web.config");

        }
    }
}