using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Text;
using System.Web;
using System.Web.Security;
using WebMatrix.WebData;
using WebMatrix.Data;
using System.Net.Mail;

namespace Historia.Framework.Providers
{
    public class Membership : ExtendedMembershipProvider
    {
        private string connectionKey = null;

        public override void Initialize(string name, System.Collections.Specialized.NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");

            if (String.IsNullOrEmpty(name))
                name = "BFCMembershipProvider";

            if (String.IsNullOrEmpty(config["description"]))
                config["description"] = "BFC Membership Provider for SQL Server";
            
            base.Initialize(name, config);

            connectionKey = config["ConnectionKey"];
            if (String.IsNullOrEmpty(connectionKey))
            {
                connectionKey = ConfigurationManager.AppSettings["ConnectionKey"];
                if (String.IsNullOrEmpty(connectionKey))
                    throw new ApplicationException("No connection key was found in the application settings.");
            }

            TryConfigParseInt("maxInvalidPasswordAttempts", out maxInvalidPasswordAttempts, 5);
            TryConfigParseInt("minRequiredPasswordLength", out minRequiredPasswordLength, 8);
            TryConfigParseInt("minRequiredNonalphanumericCharacters", out minRequiredNonAlphanumericCharacters, 0);
            TryConfigParseInt("passwordAttemptWindow", out passwordAttemptWindowMinutes, 60);
            TryConfigParseInt("passwordExpirationDays", out passwordExpirationDays, 90);
            TryConfigParseInt("minPasswordHistory", out minPasswordHistory, 4);

            passwordStrengthRegularExpression = @"^.*(?=.{8,})(((?=.*[a-z])(?=.*[A-Z])(?=.*[\W_]))|((?=.*\d)(?=.*[A-Z])(?=.*[\W_]))|((?=.*\d)(?=.*[a-z])(?=.*[\W_]))|((?=.*\d)(?=.*[a-z])(?=.*[A-Z]))).*$";
            if (!String.IsNullOrEmpty(config["passwordStrengthRegularExpression"]))
                passwordStrengthRegularExpression = config["passwordStrengthRegularExpression"];
        }

        private void TryConfigParseInt(string stringValue, out int intValue, int defaultValue)
        {
            if (String.IsNullOrEmpty(stringValue) || !int.TryParse(stringValue, out intValue))
                intValue = defaultValue;
        }

        public override bool EnablePasswordReset
        {
            get { return true; }
        }

        public override bool EnablePasswordRetrieval
        {
            get { return false; }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get { return true; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return false; }
        }

        //public override MembershipPasswordFormat PasswordFormat
        //{
        //    get { return MembershipPasswordFormat.Hashed; }
        //}

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return MembershipPasswordFormat.Hashed; }
        }

        protected int maxInvalidPasswordAttempts;
        public override int MaxInvalidPasswordAttempts
        {
            get { return maxInvalidPasswordAttempts; }
        }

        protected int minRequiredPasswordLength;
        public override int MinRequiredPasswordLength
        {
            get { return minRequiredPasswordLength; }
        }

        protected int minRequiredNonAlphanumericCharacters;
        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return minRequiredNonAlphanumericCharacters; }
        }

        protected string passwordStrengthRegularExpression;
        public override string PasswordStrengthRegularExpression
        {
            get { return passwordStrengthRegularExpression; }
        }

        protected int passwordAttemptWindowMinutes;
        public override int PasswordAttemptWindow
        {
            get { return passwordAttemptWindowMinutes; }
        }

        // custom for BFC: force them to change their password after X days
        protected int passwordExpirationDays;
        public virtual int PasswordExpirationDays
        {
            get { return passwordExpirationDays; }
        }

        // custom for BFC: they can't reuse any of the X last passwords
        protected int minPasswordHistory;
        public virtual int MinPasswordHistory
        {
            get { return minPasswordHistory; }
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new Exception("HistoriaConnectionString is required in the web.config");

            bool success = false;
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.CommandText = "pr_Membership_DeleteUser";
                    cmd.Parameters.Add("@UserName", SqlDbType.NVarChar, 100).Value = username;
                    try
                    {
                        cmd.Connection.Open();
                        success = (cmd.ExecuteNonQuery() > 0);
                    }
                    finally
                    {
                        cmd.Connection.Close();
                    }
                }
            }
            return success;
        }

        public override bool ValidateUser(string username, string password)
        {
            string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new Exception("HistoriaConnectionString is required in the web.config");

            bool success = false;
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                Guid userId = Guid.Empty;
                Security.SecurePassword pw = null;
                bool matched = false;
                bool lockedOut = false;
                bool userActive = true;
                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.CommandText = "pr_Membership_ValidateUser";
                    cmd.Parameters.Add("@UserName", SqlDbType.NVarChar, 100).Value = username;
                    cmd.Parameters.Add("@MaxAttempts", SqlDbType.Int).Value = this.MaxInvalidPasswordAttempts;
                    cmd.Parameters.Add("@LockoutMinutes", SqlDbType.Int).Value = this.PasswordAttemptWindow;
                    try
                    {
                        cmd.Connection.Open();
                        using (SqlDataReader dr = cmd.ExecuteReader())
                        {
                            if (dr.Read())
                            {
                                userId = dr.GetGuid(0);
                                if (!dr.IsDBNull(1))
                                    pw = new Security.SecurePassword((byte[])dr[1]);
                                lockedOut = true.Equals(dr[2]);
                                userActive = true.Equals(dr[3]);
                            }
                            dr.Close();
                        }
                    }
                    finally
                    {
                        cmd.Connection.Close();
                    }
                }

                if (pw != null)
                {
                    matched = pw.IsEqual(password);
                    if (matched)
                    {
                        if (pw.Encrypted.Length == 16) // automatically replace the old MD5 version
                        {
                            Security.SecurePassword newPwd = new Security.SecurePassword(pw.Password);
                            using (SqlCommand cmd = conn.CreateCommand())
                            {
                                cmd.CommandType = CommandType.StoredProcedure;
                                cmd.CommandText = "pr_Membership_ChangePasswordHashType";
                                cmd.Parameters.Add("@UserID", SqlDbType.UniqueIdentifier).Value = userId;
                                cmd.Parameters.Add("@OldPassword", SqlDbType.VarBinary, 40).Value = pw.Encrypted;
                                cmd.Parameters.Add("@NewPassword", SqlDbType.VarBinary, 40).Value = newPwd.Encrypted;
                                try
                                {
                                    cmd.Connection.Open();
                                    cmd.ExecuteNonQuery();
                                }
                                finally
                                {
                                    cmd.Connection.Close();
                                }
                            }
                        }

                        if (userActive && !lockedOut)
                        {
                            success = true;
                            if (HttpContext.Current != null)
                            {
                                try { HttpContext.Current.Session.Abandon(); }
                                catch { }
                            }
                        }
                    }
                }

                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.CommandText = "pr_Membership_AuditLogin";
                    //if (BFC.Admin.Web.Page.Current != null)       //TODO: re-implement this
                    cmd.Parameters.Add("@AuditTrailID", SqlDbType.UniqueIdentifier).Value = null; // BFC.Admin.Web.Page.Current.AuditTrailID;
                    if (HttpContext.Current != null)
                        cmd.Parameters.Add("@IPAddress", SqlDbType.VarChar, 50).Value = HttpContext.Current.Request.UserHostAddress;
                    cmd.Parameters.Add("@UserName", SqlDbType.NVarChar, 100).Value = username;
                    if (userId != Guid.Empty && !matched) // only store the hash if the user was found and the password didn't match
                        cmd.Parameters.Add("@PasswordHash", SqlDbType.Binary, 16).Value = Utility.sha256Hash(password);

                    // NOTE: the order DOES matter here...
                    byte result = byte.MaxValue;
                    if (success) // successful login
                        result = 0;
                    else if (userId == Guid.Empty) // user not found
                        result = 1;
                    else if (!userActive)
                        result = 4;
                    else if (lockedOut) // user is temporarily locked out
                        result = 3;
                    else if (!matched) // invalid password
                        result = 2;
                    cmd.Parameters.Add("@Result", SqlDbType.TinyInt).Value = result;

                    try
                    {
                        cmd.Connection.Open();
                        cmd.ExecuteNonQuery();
                    }
                    finally
                    {
                        cmd.Connection.Close();
                    }
                }
            }
            return success;
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            return GetUserInternal(providerUserKey, null, userIsOnline);
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            return GetUserInternal(null, username, userIsOnline);
        }

        protected virtual MembershipUser GetUserInternal(object userId, string username, bool userIsOnline)
        {
            string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new Exception("HistoriaConnectionString is required in the web.config");

            MembershipUser user = null;
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.CommandText = "Membership_GetUser";
                    cmd.Parameters.Add("@UserID", SqlDbType.UniqueIdentifier).Value = userId ?? DBNull.Value;
                    cmd.Parameters.Add("@UserName", SqlDbType.NVarChar, 100).Value = DBNull.Value;
                    if (!string.IsNullOrEmpty(username))
                        cmd.Parameters["@UserName"].Value = username;
                    try
                    {
                        cmd.Connection.Open();
                        using (SqlDataReader dr = cmd.ExecuteReader(CommandBehavior.SingleResult | CommandBehavior.SingleRow))
                        {
                            if (dr.Read())
                                user = GetUserFromRow(dr);
                            dr.Close();
                        }
                    }
                    finally
                    {
                        cmd.Connection.Close();
                    }
                }
            }
            return user;
        }

        protected virtual MembershipUser GetUserFromRow(IDataRecord dr)
        {
            MembershipUser user = null;
            if (dr != null)
            {
                Guid userId = (Guid)dr["ID"];
                string userName = (string)dr["UserName"];
                string emailAddress = null;
                if (!dr.IsDBNull(dr.GetOrdinal("EmailAddress")))
                    emailAddress = (string)dr["EmailAddress"];
                string passwordQuestion = null;
                if (!dr.IsDBNull(dr.GetOrdinal("PasswordQuestion")))
                    passwordQuestion = (string)dr["PasswordQuestion"];
                bool active = true.Equals(dr["Active"]);
                bool lockedOut = true.Equals(dr["LockedOut"]);
                DateTime passwordExpiresOn = DateTime.MinValue;
                if (!dr.IsDBNull(dr.GetOrdinal("PasswordExpiresOn")))
                    passwordExpiresOn = (DateTime)dr["PasswordExpiresOn"];
                DateTime lastLoggedInOn = DateTime.MinValue;
                if (!dr.IsDBNull(dr.GetOrdinal("LastLoggedInOn")))
                    lastLoggedInOn = (DateTime)dr["LastLoggedInOn"];
                DateTime lockedOutUntil = DateTime.MinValue;
                if (!dr.IsDBNull(dr.GetOrdinal("LockedOutUntil")))
                    lockedOutUntil = (DateTime)dr["LockedOutUntil"];
                user = new MembershipUser(this.Name, userName, userId, emailAddress, passwordQuestion, null, active, lockedOut, DateTime.MinValue, lastLoggedInOn, lastLoggedInOn, passwordExpiresOn, lockedOutUntil);
            }
            return user;
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            if (String.IsNullOrEmpty(newPassword))
                throw new ArgumentException("The new password is required.");

            if (oldPassword != null && newPassword == oldPassword)
                throw new ArgumentException("The new password must be different than the current password.");

            if (newPassword.Length < this.MinRequiredPasswordLength)
                throw new ArgumentException(String.Format("The new password must be at least {0} characters long.", this.MinRequiredPasswordLength));

            if (System.Text.RegularExpressions.Regex.Replace(newPassword, @"[^\W_]", "").Length < this.MinRequiredNonAlphanumericCharacters)
                throw new ArgumentException(String.Format("The new password must contain at least {0} symbolic {1}.", this.MinRequiredNonAlphanumericCharacters, (this.MinRequiredNonAlphanumericCharacters == 1 ? "character" : "characters")));

            if (!String.IsNullOrEmpty(this.PasswordStrengthRegularExpression) && !System.Text.RegularExpressions.Regex.IsMatch(newPassword, this.PasswordStrengthRegularExpression))
                throw new ArgumentException(String.Format("The new password does not meet the minimum requirements."));

            string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new Exception("HistoriaConnectionString is required in the web.config");

            bool oldPasswordMatched = true;
            bool noHistoricalMatch = true;
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.CommandText = "pr_Membership_GetPasswordHistory";
                    cmd.Parameters.Add("@UserName", SqlDbType.NVarChar, 100).Value = username ?? "";
                    cmd.Parameters.Add("@CurrentPassword", SqlDbType.VarBinary, 40).Direction = ParameterDirection.Output;
                    cmd.Parameters.Add("@MinimumDays", SqlDbType.Int).Value = (this.passwordExpirationDays * this.minPasswordHistory);
                    try
                    {
                        cmd.Connection.Open();
                        using (SqlDataReader dr = cmd.ExecuteReader())
                        {
                            int count = 0;
                            while (dr.Read() && noHistoricalMatch && (++count <= this.MinPasswordHistory || true.Equals(dr["Restricted"])))
                            {
                                Security.SecurePassword lastPass = new Historia.Framework.Security.SecurePassword((byte[])dr["Password"]);
                                noHistoricalMatch = !lastPass.IsEqual(newPassword);
                            }
                            dr.Close();
                        }
                    }
                    finally
                    {
                        cmd.Connection.Close();
                    }
                    if (!Convert.IsDBNull(cmd.Parameters["@CurrentPassword"].Value))
                    {
                        Security.SecurePassword currPass = new Historia.Framework.Security.SecurePassword((byte[])cmd.Parameters["@CurrentPassword"].Value);
                        oldPasswordMatched = currPass.IsEqual(oldPassword);
                    }
                }
            }

            if (!oldPasswordMatched)
                throw new ArgumentException("The current password was not correct.");
            else if (!noHistoricalMatch)
                throw new ArgumentException("Please create a new password that has not been used recently.");

            return SetUserPassword(username, newPassword, false);
        }

        protected virtual string GeneratePassword(string username, bool newUser)
        {
            int minLength = 14;
            if (this.MinRequiredPasswordLength > 14)
                minLength = this.MinRequiredPasswordLength;
            int minSymbols = 2;
            if (this.MinRequiredNonAlphanumericCharacters > 2)
                minSymbols = this.MinRequiredNonAlphanumericCharacters;

            ValidatePasswordEventArgs vpa = null;
            string pass = null;
            int tries = 0;
            do
            {
                pass = System.Web.Security.Membership.GeneratePassword(minLength, minSymbols);
                if (String.IsNullOrEmpty(this.PasswordStrengthRegularExpression) || System.Text.RegularExpressions.Regex.IsMatch(pass, this.PasswordStrengthRegularExpression))
                {
                    vpa = new ValidatePasswordEventArgs(username, pass, newUser);
                    this.OnValidatingPassword(vpa);
                    if (!vpa.Cancel)
                        break; // if it meets the requirements, we can break out
                }
            }
            while (++tries < 5); // try 5 times, if it still doesn't meet them, then just use it

            if (vpa != null && vpa.Cancel)
            {
                if (vpa.FailureInformation != null)
                    throw vpa.FailureInformation;
                throw new System.Configuration.Provider.ProviderException("The auto-generated password did not meet the validation requirements.");
            }

            return pass;
        }

        public override string ResetPassword(string username, string answer)
        {
            if (!this.EnablePasswordReset)
                throw new NotSupportedException();

            string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new Exception("HistoriaConnectionString is required in the web.config");

            // if an admin resets (with a null answer parameter) then we allow it
            bool correctAnswer = (answer == null ? true : false);
            string sendEmailFrom = null;
            string sendEmailTo = null;
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.CommandText = "pr_Membership_CheckResetInfo";
                    cmd.Parameters.Add("@UserName", SqlDbType.NVarChar, 100).Value = username;
                    cmd.Parameters.Add("@Answer", SqlDbType.NVarChar, 100).Value = (answer ?? "");
                    try
                    {
                        cmd.Connection.Open();
                        using (SqlDataReader dr = cmd.ExecuteReader())
                        {
                            if (dr.Read())
                            {
                                correctAnswer = correctAnswer || true.Equals(dr["CorrectAnswer"]);
                                if (!dr.IsDBNull(dr.GetOrdinal("ManagerEmail")))
                                    sendEmailFrom = (string)dr["ManagerEmail"];
                                if (!dr.IsDBNull(dr.GetOrdinal("UserEmail")))
                                    sendEmailTo = (string)dr["UserEmail"];
                            }
                            else // if the user wasn't found, it failed even if you are an admin
                                correctAnswer = false;
                        }
                    }
                    finally
                    {
                        cmd.Connection.Close();
                    }
                }
            }

            if (!correctAnswer)
                throw new System.Configuration.Provider.ProviderException("The password answer does not match the specified user.");
            else if (String.IsNullOrEmpty(sendEmailTo))
                throw new System.Configuration.Provider.ProviderException("This user does not have a valid email address.");
            else if (String.IsNullOrEmpty(sendEmailFrom))
                sendEmailFrom = sendEmailTo; // if no manager, email will look like it came from the user

            string ret = null;

            string pass = GeneratePassword(username, false);
            if (!String.IsNullOrEmpty(pass))
            {
                if (SetUserPassword(username, pass, true))
                {
                    ret = pass;

                    // send a message to the user
                   /* MailMessage mm = new MailMessage();
                    mm.From = sendEmailFrom;
                    mm.To = sendEmailTo;
                    mm.Subject = "Password Reset";
                    mm.Body = String.Format("Your password has been reset to:{0}{1}{0}{0}You may use this temporary password to log in to the site.{0}Please contact an administrator if you need further assistance.", Environment.NewLine, pass);
                    mm.
                    mm.Send();*/
                }
            }

            if (ret == null)
                throw new System.Configuration.Provider.ProviderException("Unable to reset the user's password.");

            return ret;
        }

        protected virtual bool SetUserPassword(string username, string password, bool expireNow)
        {
            string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new Exception("HistoriaConnectionString is required in the web.config");

            bool success = false;
            if (!String.IsNullOrEmpty(password))
            {
                Security.SecurePassword newpass = new Historia.Framework.Security.SecurePassword(password);
                using (SqlConnection conn = new SqlConnection(connectionString))
                {
                    using (SqlCommand cmd = conn.CreateCommand())
                    {
                        cmd.CommandType = CommandType.StoredProcedure;
                        cmd.CommandText = "pr_Membership_ChangePassword";
                        cmd.Parameters.Add("@UserName", SqlDbType.NVarChar, 100).Value = username;
                        cmd.Parameters.Add("@Password", SqlDbType.VarBinary, 40).Value = newpass.Encrypted;
                        cmd.Parameters.Add("@ExpireInDays", SqlDbType.Int).Value = (expireNow ? 0 : this.passwordExpirationDays);
                        try
                        {
                            cmd.Connection.Open();
                            success = (cmd.ExecuteNonQuery() > 0);
                        }
                        finally
                        {
                            cmd.Connection.Close();
                        }
                    }
                }
            }
            return success;
        }

        public override bool UnlockUser(string userName)
        {
            string connectionString = ConfigurationManager.ConnectionStrings["HistoriaConnectionString"].ConnectionString;
            if (String.IsNullOrEmpty(connectionString))
                throw new Exception("HistoriaConnectionString is required in the web.config");

            bool success = false;
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                using (SqlCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandType = CommandType.StoredProcedure;
                    cmd.CommandText = "pr_Membership_UnlockUser";
                    cmd.Parameters.Add("@UserName", SqlDbType.NVarChar, 100).Value = userName;
                    try
                    {
                        cmd.Connection.Open();
                        success = (cmd.ExecuteNonQuery() > 0);
                    }
                    finally
                    {
                        cmd.Connection.Close();
                    }
                }
            }
            return success;
        }

        public override string ApplicationName
        {
            get { return "BFC.Framework"; }
            set { throw new NotSupportedException(); }
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotSupportedException();
        }

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override int GetNumberOfUsersOnline()
        {
            throw new NotSupportedException();
        }

        public override string GetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        public override string GetUserNameByEmail(string email)
        {
            throw new NotSupportedException();
        }

        public override void UpdateUser(MembershipUser user)
        {
            throw new NotSupportedException();
        }

        //New WebMaxtrix functions
        public override bool ConfirmAccount(string accountConfirmationToken)
        {
            throw new NotImplementedException();
        }
        public override bool ConfirmAccount(string userName, string accountConfirmationToken)
        {
            throw new NotImplementedException();
        }
        //Need to implement this: 
        public override string CreateAccount(string userName, string password)
        {
            return base.CreateAccount(userName, password);
        }
        public override string CreateAccount(string userName, string password, bool requireConfirmationToken)
        {
            throw new NotImplementedException();
        }
        //need to implement this
        public override string CreateUserAndAccount(string userName, string password)
        {
            return base.CreateUserAndAccount(userName, password);
        }
        public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation, IDictionary<string, object> values)
        {
            throw new NotImplementedException();
        }

        public override bool DeleteAccount(string userName)
        {
            return DeleteUser(userName, true);
        }
        public override string GeneratePasswordResetToken(string userName)
        {
            return base.GeneratePasswordResetToken(userName);
        }
        public override string GeneratePasswordResetToken(string userName, int tokenExpirationInMinutesFromNow)
        {
            throw new NotImplementedException();
        }
        public override ICollection<OAuthAccountData> GetAccountsForUser(string userName)
        {
            throw new NotImplementedException();
        }
        public override DateTime GetCreateDate(string userName)
        {
            throw new NotImplementedException();
        }
        public override DateTime GetLastPasswordFailureDate(string userName)
        {
            throw new NotImplementedException();
        }
        public override DateTime GetPasswordChangedDate(string userName)
        {
            throw new NotImplementedException();
        }
        public override int GetPasswordFailuresSinceLastSuccess(string userName)
        {
            throw new NotImplementedException();
        }
        public override int GetUserIdFromPasswordResetToken(string token)
        {
            throw new NotImplementedException();
        }
        public override bool IsConfirmed(string userName)
        {
            throw new NotImplementedException();
        }
        public override bool ResetPasswordWithToken(string token, string newPassword)
        {
            throw new NotImplementedException();
        }
    }
}
