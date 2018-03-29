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
    public class Culture
    {
        public string Code { get; set; }

        public string Name { get; set; }
    }

    public class CultureModel
    {
        [Key]
        public List<Culture> AvailableCultures { get; set; }


        public CultureModel()
        {
            this.AvailableCultures = new List<Culture>();

            string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new Exception("HistoriaConnectionString is required in the web.config");

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "Historia_GetCultureCodes";
                    cmd.CommandType = CommandType.StoredProcedure;
                    using (SqlDataReader rdr = cmd.ExecuteReader())
                    {
                        while (rdr.Read())
                        {
                            this.AvailableCultures.Add(new Culture() { Code = rdr[1].ToString(), Name = rdr[2].ToString() });
                        }
                    }
                }
            }
        }
    }
}