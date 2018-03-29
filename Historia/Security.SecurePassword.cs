using System;

namespace Historia.Framework.Security
{ 
    public class SecurePassword
    {
        private const int SaltLength = 8;
        private const int HashLength = 32; // should be a multiple of SaltLength

        public SecurePassword(string password)
        {
            if (password != null && password.Length > 0)
                _password = password;
            else
                throw new ArgumentException("The password cannot be blank.");
        }

        public SecurePassword(byte[] data)
        {
            if (data != null && (data.Length == 32 || data.Length == SaltLength + HashLength))
                _encrypted = (byte[])data.Clone();
            else
                //Updated by Kary to work for passwords that used to be varchar and were converted to varbinary (which SQL doesnt do the way we want, i.e. 8 becomes 38 etc...)
                _encrypted = Historia.Framework.Utility.HexToBytes(Historia.Framework.Utility.BytesToString(data));

            if (_encrypted != null)
            {
                if (_encrypted.Length == 32)
                    _hash = _encrypted; // it's a plain MD5 hash
                else
                {
                    _salt = new byte[SaltLength];
                    _hash = new byte[HashLength];

                    int blockSize = _hash.Length / _salt.Length;
                    for (int i = 0; i < Salt.Length; i++)
                    {
                        Array.Copy(_encrypted, ((i + 1) * (blockSize + 1) - 1), _salt, i, 1);
                        Array.Copy(_encrypted, i * (blockSize + 1), _hash, i * blockSize, blockSize);
                    }
                }
            }
            else
                throw new ArgumentException("The encrypted password data is invalid.");
        }

        public bool IsEqual(string password)
        {
            byte[] testHash;
            if (_encrypted.Length == 32) // test against the MD5 hash
                testHash = Historia.Framework.Utility.sha256Hash(password);
            else
                testHash = ComputeHash(password);

            bool isEqual = (Hash.Length == testHash.Length);
            if (isEqual)
            {
                for (int i = 0; i < testHash.Length; i++)
                    if (testHash[i] != Hash[i])
                    {
                        isEqual = false;
                        break;
                    }
            }

            if (isEqual && _password.Length < 1)
                _password = password;

            return isEqual;
        }

        public override string ToString()
        {
            return Historia.Framework.Utility.BytesToHex(Encrypted);
        }

        private byte[] _encrypted = null;
        public byte[] Encrypted
        {
            get
            {
                if (_encrypted == null)
                {
                    _encrypted = new byte[Salt.Length + Hash.Length];
                    int blockSize = Hash.Length / Salt.Length;
                    for (int i = 0; i < Salt.Length; i++)
                    {
                        Array.Copy(Salt, i, _encrypted, ((i + 1) * (blockSize + 1) - 1), 1);
                        Array.Copy(Hash, i * blockSize, _encrypted, i * (blockSize + 1), blockSize);
                    }
                }
                return _encrypted;
            }
        }

        private string _password = String.Empty;
        public string Password
        {
            get
            {
                return _password;
            }
        }

        private byte[] _salt = null;
        protected byte[] Salt
        {
            get
            {
                if (_salt == null)
                    _salt = CreateRandomSalt();
                return _salt;
            }
        }

        private byte[] _hash = null;
        protected byte[] Hash
        {
            get
            {
                if (_hash == null)
                    _hash = ComputeHash(_password);
                return _hash;
            }
        }

        private byte[] CreateRandomSalt()
        {
            byte[] randomSalt = new byte[SaltLength];
            System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider();
            rng.GetBytes(randomSalt);
            return randomSalt;
        }

        private byte[] ComputeHash(string password)
        {
            byte[] pwd = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] data = new byte[pwd.Length + Salt.Length];

            Array.Copy(pwd, 0, data, 0, pwd.Length);
            Array.Copy(Salt, 0, data, pwd.Length, Salt.Length);

            return System.Security.Cryptography.SHA256Managed.Create().ComputeHash(data);
        }
    }

}
