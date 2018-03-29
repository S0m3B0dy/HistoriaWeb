using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Data.SqlClient;
using System.Linq;
using System.Web;
using System.Web.Security;

namespace Historia
{
    public sealed class CustomRoleProvider : RoleProvider
    {
        private string applicationName;

        public override string ApplicationName
        {
            get
            {
                return applicationName;
            }
            set
            {
                applicationName = value;
            }
        }

        /// <summary>
        /// Initialize.
        /// </summary>
        /// <param name="usernames"></param>
        /// <param name="roleNames"></param>
        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }

            if (name == null || name.Length == 0)
            {
                name = "CustomRoleProvider";
            }

            if (String.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Custom Role Provider");
            }

            //Initialize the abstract base class.
            base.Initialize(name, config);

            applicationName = GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
        }

        /// <summary>
        /// Add users to roles.
        /// </summary>
        /// <param name="usernames"></param>
        /// <param name="roleNames"></param>
        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
 
        }

        /// <summary>
        /// Create new role.
        /// </summary>
        /// <param name="roleName"></param>
        public override void CreateRole(string roleName)
        {

        }

        /// <summary>
        /// Delete role.
        /// </summary>
        /// <param name="roleName"></param>
        /// <param name="throwOnPopulatedRole"></param>
        /// <returns>true if role is successfully deleted</returns>
        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            bool ret = false;

            return ret;
        }

        /// <summary>
        /// Find users in role.
        /// </summary>
        /// <param name="roleName"></param>
        /// <param name="usernameToMatch"></param>
        /// <returns></returns>
        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            List<string> users = new List<string>();

            return users.ToArray();
        }

        /// <summary>
        /// Get all roles.
        /// </summary>
        /// <returns></returns>
        public override string[] GetAllRoles()
        {
            List<string> roles = new List<string>();

            return roles.ToArray();
        }

        /// <summary>
        /// Get all roles for a specific user.
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        public override string[] GetRolesForUser(string username)
        {
            List<string> roles = new List<string>();

            return roles.ToArray();
        }

        /// <summary>
        /// Get all users that belong to a role.
        /// </summary>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public override string[] GetUsersInRole(string roleName)
        {
            List<string> users = new List<string>();

            return users.ToArray();
        }

        /// <summary>
        /// Checks if user belongs to a given role.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public override bool IsUserInRole(string username, string roleName)
        {
            bool isInRole = false;


            string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new Exception("HistoriaConnectionString is required in the web.config");

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                Guid userId = Guid.Empty;
                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT * FROM Users WHERE UserName = @UserName";
                    cmd.Parameters.Add("UserName", System.Data.SqlDbType.NVarChar, 100).Value = username;

                    using (SqlDataReader rdr = cmd.ExecuteReader())
                    {
                        if (rdr.Read())
                        {
                            userId = rdr.GetGuid(rdr.GetOrdinal("ID"));
                        }
                        else
                        {
                            return isInRole;
                        }
                    }
                }

                int roleId = -1;
                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT * FROM Roles WHERE RoleName = @RoleName";
                    cmd.Parameters.Add("RoleName", System.Data.SqlDbType.NVarChar, 100).Value = roleName;

                    using (SqlDataReader rdr = cmd.ExecuteReader())
                    {
                        if (rdr.Read())
                        {
                            roleId = rdr.GetInt32(rdr.GetOrdinal("Id"));
                        }
                        else
                        {
                            return isInRole;
                        }
                    }
                }

                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT * FROM UserRoles WHERE UserId = @UserID AND RoleId = @RoleID";
                    cmd.Parameters.Add("UserID", System.Data.SqlDbType.UniqueIdentifier).Value = userId;
                    cmd.Parameters.Add("RoleID", System.Data.SqlDbType.Int).Value = roleId;

                    using (SqlDataReader rdr = cmd.ExecuteReader())
                    {
                        if (rdr.Read())
                        {
                            isInRole = true;
                        }
                    }
                }
            }

            return isInRole;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="usernames"></param>
        /// <param name="roleNames"></param>
        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
        }

        /// <summary>
        /// Check if role exists.
        /// </summary>
        /// <param name="configValue"></param>
        /// <param name="defaultValue"></param>
        /// <returns></returns>
        public override bool RoleExists(string roleName)
        {
            return false;
        }

        /// <summary>
        /// Get config value.
        /// </summary>
        /// <param name="configValue"></param>
        /// <param name="defaultValue"></param>
        /// <returns></returns>
        private string GetConfigValue(string configValue, string defaultValue)
        {
            if (String.IsNullOrEmpty(configValue))
            {
                return defaultValue;
            }

            return configValue;
        }
    }
}