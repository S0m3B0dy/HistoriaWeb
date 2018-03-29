using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Historia.Resources.ResourceProviders
{
    public class LocalizationDbResourceProvider : LocalizationResourceProviderBase
    {
        private string _connectionString;

        public LocalizationDbResourceProvider()
            : this(Constants.CONNSTRING_DEFAULT_NAME)
        {
        }

        public LocalizationDbResourceProvider(string connectionStringName)
            : base()
        {
            _connectionString = ConfigurationManager.ConnectionStrings[connectionStringName].ConnectionString;
        }

        protected override string OnGetString(string cultureName, string key)
        {
            using(var conn = new SqlConnection(_connectionString))
            {
                using(var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "ResourceLookup";
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    cmd.Parameters.Add("@key", System.Data.SqlDbType.NVarChar,100).Value = key;
                    cmd.Parameters.Add("@culture", System.Data.SqlDbType.NVarChar,20).Value = cultureName;
                    conn.Open();

                    using (SqlDataReader res = cmd.ExecuteReader())
                    {
                        if (res.Read())
                        {
                            try
                            {
                                var value = res["Value"].ToString();
                                return (string)value;
                            }
                            catch (Exception e)
                            {
                            }
                        }
                        else
                        {
                            return String.Empty;
                        }
                    }
                    return String.Empty;
                }
            }
        }

        protected override byte[] OnGetBinary(string cultureName, string key)
        {
            byte[] result = null;
            using (var conn = new SqlConnection(_connectionString))
            {
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "ResourceLookup";
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    cmd.Parameters.Add("@key", System.Data.SqlDbType.NVarChar, 100).Value = key;
                    cmd.Parameters.Add("@culture", System.Data.SqlDbType.NVarChar, 20).Value = cultureName;
                    conn.Open();

                    using (SqlDataReader res = cmd.ExecuteReader())
                    {
                        if (res.Read())
                        {
                            try
                            {
                                if ( !res.IsDBNull(res.GetOrdinal("BinFile")))
                                    result = res.GetSqlBytes(res.GetOrdinal("BinFile")).Value;                               
                                return result;
                            }
                            catch (Exception e)
                            {
                            }
                        }
                        else
                        {
                            return result;
                        }
                    }
                    return result;
                }
            }
        }

        protected override bool OnSetBinary(string cultureName, string key, byte[] value, string resourceSet)
        {
            try
            {
                using (var conn = new SqlConnection(_connectionString))
                {
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = "ResourceSetBinary";
                        cmd.CommandType = System.Data.CommandType.StoredProcedure;
                        cmd.Parameters.Add("@Key", System.Data.SqlDbType.NVarChar, 100).Value = key;
                        cmd.Parameters.Add("@Culture", System.Data.SqlDbType.NVarChar, 20).Value = cultureName;
                        cmd.Parameters.Add("@Value", System.Data.SqlDbType.Image).Value = value;
                        if(!string.IsNullOrEmpty(resourceSet))
                            cmd.Parameters.Add("@ResourceSet", System.Data.SqlDbType.NVarChar, 512).Value = resourceSet;
                        conn.Open();

                        cmd.ExecuteNonQuery();
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Historia.Framework.Utility.Log(ex.ToString());
                return false;
            }
        }

        protected override bool OnSetString(string cultureName, string key, string value, string resourceSet)
        {
            try
            {
                using (var conn = new SqlConnection(_connectionString))
                {
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = "ResourceSetString";
                        cmd.CommandType = System.Data.CommandType.StoredProcedure;
                        cmd.Parameters.Add("@Key", System.Data.SqlDbType.NVarChar, 100).Value = key;
                        cmd.Parameters.Add("@Culture", System.Data.SqlDbType.NVarChar, 20).Value = cultureName;
                        cmd.Parameters.Add("@Value", System.Data.SqlDbType.NText).Value = value;
                        if (!string.IsNullOrEmpty(resourceSet))
                            cmd.Parameters.Add("@ResourceSet", System.Data.SqlDbType.NVarChar, 512).Value = resourceSet;
                        conn.Open();

                        cmd.ExecuteNonQuery();
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Historia.Framework.Utility.Log(ex.ToString());
                return false;
            }
        }
    }
}
