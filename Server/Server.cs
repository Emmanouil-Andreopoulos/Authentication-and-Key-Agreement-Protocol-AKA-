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

                    //Convert Certificate to bytes and send to client
                    handler.Send(Certificate.Export(X509ContentType.Cert));




                    bytes = new byte[1024];
                    bytesRec = handler.Receive(bytes);
                    string en_RN = Encoding.ASCII.GetString(bytes, 0, bytesRec);
                    string RN = en_RN;//for testing
                    //TODO: decrypt en_RN with private key
                    SHA256 mySHA256 = SHA256Managed.Create();

                    //Cookie_Server | Cookie_Client | RN
                    String C_server_C_client_RN = GetSHA256Hash(mySHA256, Cookie + Client_Cookie + RN);

                    Console.WriteLine("SHA256: {0}", C_server_C_client_RN);

                    //Split SHA256(Cookie_Server | Cookie_Client | RN) in half to make key1 key2
                    string key1 = C_server_C_client_RN.Substring(0, (int)(C_server_C_client_RN.Length / 2));
                    string key2 = C_server_C_client_RN.Substring((int)(C_server_C_client_RN.Length / 2), (int)(C_server_C_client_RN.Length / 2));

                    Console.WriteLine("Key1: {0}", key1);
                    Console.WriteLine("Key2: {0}", key2);
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

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
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
