using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Historia.Framework
{
    public class Utility
    {
        public static byte[] sha256Hash(string stringToHash)
        {
            var crypt = new System.Security.Cryptography.SHA256Managed();
            var hash = new System.Text.StringBuilder();
            byte[] crypto = crypt.ComputeHash(Encoding.UTF8.GetBytes(stringToHash));

            return crypto;
        }

        public static void Log(string msg, [CallerMemberName] string methodName = "")
        {

            //LogToDatabase(formattedMsg, 1, Assembly.GetCallingAssembly(), null);
        }

        public static string BytesToString(byte[] data)
        {
            if (data == null)
                return null;

            return Encoding.UTF8.GetString(data);
        }

        public static byte[] StringToBytes(string str)
        {
            if (str == null)
                return null;

            return Encoding.UTF8.GetBytes(str);
        }

        public static string BytesToHex(byte[] data)
        {
            if (data == null)
                return null;

            if (data.Length == 0)
                return String.Empty;

            return BitConverter.ToString(data).Replace("-", "").ToUpper();
        }

        public static string BytesToHex(byte[] data, int startIndex)
        {
            return BitConverter.ToString(data, startIndex).ToUpper().Replace("-", "");
        }

        public static string BytesToHex(byte[] data, int startIndex, int length)
        {
            return BitConverter.ToString(data, startIndex, length).ToUpper().Replace("-", "");
        }

        public static byte[] HexToBytes(string str)
        {
            if (str == null)
                return null;

            str = System.Text.RegularExpressions.Regex.Replace(str.ToUpper(), @"[^0-9A-F]", "");

            byte[] data = new byte[str.Length / 2];
            for (int i = 0; i < data.Length; i++)
                data[i] = byte.Parse(str.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
            return data;
        }
    }
}
