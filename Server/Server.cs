using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using BlowFishCS;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Server
{
    class Server
    {
        // Incoming data from the client.  
        public static string data = null;

        private static string GenerateRandomBits(int size)
        {
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] tokenData = new byte[size / 8];// 1 byte = 8 bits
                rng.GetBytes(tokenData);

                return Convert.ToBase64String(tokenData);
            }
        }

        public static void StartListening() {  
            // Data buffer for incoming data.  
            byte[] bytes = new Byte[1024];  

            // Establish the local endpoint for the socket.  
            // Dns.GetHostName returns the name of the   
            // host running the application.  
            IPHostEntry ipHostInfo = Dns.GetHostEntry("127.0.0.1");  
            IPAddress ipAddress = ipHostInfo.AddressList[0];  
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 11000);

            // Create a TCP/IP socket.  
            Socket listener = new Socket(AddressFamily.InterNetwork,  
                SocketType.Stream, ProtocolType.Tcp );  

            // Bind the socket to the local endpoint and   
            // listen for incoming connections.  
            try {  
                listener.Bind(localEndPoint);  
                listener.Listen(10);

                // Start listening for connections.  
                Console.WriteLine("Waiting for a connection...");
                // Program is suspended while waiting for an incoming connection.  
                Socket handler = listener.Accept();
                data = null;

                // An incoming connection needs to be processed.  
                bytes = new byte[1024];
                int bytesRec = handler.Receive(bytes);
                data = Encoding.ASCII.GetString(bytes, 0, bytesRec);

                // Show the data on the console.  
                Console.WriteLine("Text received: {0}", data);

                // Generate 64bits Cookie
                string Cookie = GenerateRandomBits(64);

                Console.WriteLine("Cookie: {0}", Cookie);

                // Send 64bits Cookie to client 
                handler.Send(Encoding.ASCII.GetBytes(Cookie));

                // Receive back Cookie from client
                bytes = new byte[1024];
                bytesRec = handler.Receive(bytes);
                data = Encoding.ASCII.GetString(bytes, 0, bytesRec);

                // Check if received cookie is ok
                if (Cookie.Equals(data))
                {
                    Console.WriteLine("Cookie check OK!");

                    // Receive Client Cookie
                    bytes = new byte[1024];
                    bytesRec = handler.Receive(bytes);
                    string Client_Cookie = Encoding.ASCII.GetString(bytes, 0, bytesRec);

                    Console.WriteLine("Client Cookie: {0}", Client_Cookie);

                    string[] client_suites = new string[4];

                    // Receive supported suites from client
                    bytes = new byte[1024];
                    bytesRec = handler.Receive(bytes);
                    client_suites[0] = Encoding.ASCII.GetString(bytes, 0, bytesRec);

                    Console.WriteLine("Supported Client suite 1: {0}", client_suites[0]);

                    bytes = new byte[1024];
                    bytesRec = handler.Receive(bytes);
                    client_suites[1] = Encoding.ASCII.GetString(bytes, 0, bytesRec);

                    Console.WriteLine("Supported Client suite 2: {0}", client_suites[1]);

                    bytes = new byte[1024];
                    bytesRec = handler.Receive(bytes);
                    client_suites[2] = Encoding.ASCII.GetString(bytes, 0, bytesRec);

                    Console.WriteLine("Supported Client suite 3: {0}", client_suites[2]);

                    bytes = new byte[1024];
                    bytesRec = handler.Receive(bytes);
                    client_suites[3] = Encoding.ASCII.GetString(bytes, 0, bytesRec);

                    Console.WriteLine("Supported Client suite 4: {0}", client_suites[3]);

                    //Send back the chosen suites
                    handler.Send(Encoding.ASCII.GetBytes(client_suites[1]));
                    System.Threading.Thread.Sleep(100);
                    handler.Send(Encoding.ASCII.GetBytes(client_suites[3]));
                    System.Threading.Thread.Sleep(50);

                    //Read certificate from file
                    X509Certificate2 Certificate = new X509Certificate2("..//..//my-cert.pem");
                    Console.WriteLine(Certificate.ToString(true));

                    //Convert Certificate to bytes and send to client
                    handler.Send(Certificate.Export(X509ContentType.Cert));

                    bytes = new byte[256];
                    bytesRec = handler.Receive(bytes);

                    //decrypt RN with private key
                    X509Certificate2 Certificate2 = new X509Certificate2("..//..//AKA-cert.pfx","password123");
                    RSACryptoServiceProvider RSACSP = (RSACryptoServiceProvider)Certificate2.PrivateKey;
                    string RN = Encoding.ASCII.GetString(RSACSP.Decrypt(bytes,false));
                    Console.WriteLine("RN: {0}", RN);
                    SHA256 mySHA256 = SHA256Managed.Create();

                    //Cookie_Server | Cookie_Client | RN
                    String C_server_C_client_RN = GetSHA256Hash(mySHA256, Cookie + Client_Cookie + RN);

                    Console.WriteLine("SHA256: {0}", C_server_C_client_RN);

                    //Split SHA256(Cookie_Server | Cookie_Client | RN) in half to make key1 key2
                    string key1 = C_server_C_client_RN.Substring(0, (int)(C_server_C_client_RN.Length / 2));
                    string key2 = C_server_C_client_RN.Substring((int)(C_server_C_client_RN.Length / 2), (int)(C_server_C_client_RN.Length / 2));

                    Console.WriteLine("Key1: {0}", key1);
                    Console.WriteLine("Key2: {0}", key2);

                    bytes = new byte[1024];
                    bytesRec = handler.Receive(bytes);
                    String hmac = Encoding.ASCII.GetString(bytes, 0, bytesRec);

                    HMACSHA256 hmac1 = new HMACSHA256(Encoding.ASCII.GetBytes(key2));
                    if (VerifyHMACSHA256Hash(hmac1,client_suites[1]+client_suites[3],hmac))
                    {
                        Console.WriteLine("HMAC is valid!");

                        //
                        handler.Send(Encoding.ASCII.GetBytes(EncryptString("acknowledgement_done", Encoding.ASCII.GetBytes(key1))));
                    }
                    else
                    {
                        Console.WriteLine("HMAC is not valid!");
                    }
                }

                handler.Shutdown(SocketShutdown.Both);
                handler.Close();

            } catch (Exception e) {  
                Console.WriteLine(e.ToString());  
            }  

            Console.WriteLine("\nPress ENTER to continue...");  
            Console.Read();  

        } 


        public static int Main(String[] args) {  
            StartListening();  
            return 0;  
        }

        //msdn.microsoft.com/en-us/library/
        static string GetMd5Hash(MD5 md5Hash, string input)
        {

            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        // Verify a hash against a string.
        static bool VerifyMd5Hash(MD5 md5Hash, string input, string hash)
        {
            // Hash the input.
            string hashOfInput = GetMd5Hash(md5Hash, input);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        static string GetSHA256Hash(SHA256 mySHA256, string input)
        {
            // Convert the input string to a byte array and compute the hash.
            byte[] data = mySHA256.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        // Verify a hash against a string.
        static bool VerifySHA256Hash(SHA256 mySHA256, string input, string hash)
        {
            // Hash the input.
            string hashOfInput = GetSHA256Hash(mySHA256, input);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        static string EncryptString(string plainText, byte[] Key)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");

            using (Aes _aesAlg = Aes.Create())
            {
                _aesAlg.Key = Key;
                ICryptoTransform _encryptor = _aesAlg.CreateEncryptor(_aesAlg.Key, _aesAlg.IV);

                using (MemoryStream _memoryStream = new MemoryStream())
                {
                    _memoryStream.Write(_aesAlg.IV, 0, 16);
                    using (CryptoStream _cryptoStream = new CryptoStream(_memoryStream, _encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter _streamWriter = new StreamWriter(_cryptoStream))
                        {
                            _streamWriter.Write(plainText);
                        }
                        return Convert.ToBase64String(_memoryStream.ToArray());
                    }
                }
            }
        }


        static string DecryptString(string cipherText, byte[] Key)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");

            string plaintext = null;

            byte[] _initialVector = new byte[16];
            byte[] _cipherTextBytesArray = Convert.FromBase64String(cipherText);
            byte[] _originalString = new byte[_cipherTextBytesArray.Length - 16];

            Array.Copy(_cipherTextBytesArray, 0, _initialVector, 0, 16);
            Array.Copy(_cipherTextBytesArray, 16, _originalString, 0, _cipherTextBytesArray.Length - 16);

            using (Aes _aesAlg = Aes.Create())
            {
                _aesAlg.Key = Key;
                _aesAlg.IV = _initialVector;
                ICryptoTransform decryptor = _aesAlg.CreateDecryptor(_aesAlg.Key, _aesAlg.IV);

                using (MemoryStream _memoryStream = new MemoryStream(_originalString))
                {
                    using (CryptoStream _cryptoStream = new CryptoStream(_memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader _streamReader = new StreamReader(_cryptoStream))
                        {
                            plaintext = _streamReader.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;
        }

        static string GetHMACSHA256Hash(HMACSHA256 myHMACSHA256, string input)
        {
            // Convert the input string to a byte array and compute the hash.
            byte[] data = myHMACSHA256.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        // Verify a hash against a hash.
        static bool VerifyHMACSHA256Hash(HMACSHA256 myHMACSHA256, string input, string hash)
        {
            // Hash the input.
            string hashOfInput = GetHMACSHA256Hash(myHMACSHA256, input);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
