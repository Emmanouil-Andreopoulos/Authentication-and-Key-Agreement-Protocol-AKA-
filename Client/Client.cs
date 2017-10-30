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

namespace Client
{
    class Client
    {
        private static string GenerateRandomBits(int size)
        {
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] tokenData = new byte[size/8];// 1 byte = 8 bits
                rng.GetBytes(tokenData);

                return Convert.ToBase64String(tokenData);
            }
        }

        public static void StartClient() {  
            // Data buffer for incoming data.  
            byte[] bytes = new byte[1024];  

            // Connect to a remote device.  
            try {  
                // Establish the remote endpoint for the socket.  
                // This example uses port 11000 on the local computer.  
                IPHostEntry ipHostInfo = Dns.GetHostEntry("127.0.0.1");  
                IPAddress ipAddress = ipHostInfo.AddressList[0];  
                IPEndPoint remoteEP = new IPEndPoint(ipAddress,11000);  

                // Create a TCP/IP  socket.  
                Socket sender = new Socket(AddressFamily.InterNetwork,   
                    SocketType.Stream, ProtocolType.Tcp );  

                // Connect the socket to the remote endpoint. Catch any errors.  
                try {  
                    sender.Connect(remoteEP);  

                    Console.WriteLine("Socket connected to {0}",  
                        sender.RemoteEndPoint.ToString());  

                    // Encode the Hello string into a byte array.  
                    byte[] msg = Encoding.ASCII.GetBytes("Hello");  

                    // Send Hello through the socket.  
                    int bytesSent = sender.Send(msg);  

                    // Receive 64bits Cookie from server
                    int bytesRec = sender.Receive(bytes);
                    string Server_Cookie = Encoding.ASCII.GetString(bytes, 0, bytesRec);
                    Console.WriteLine("Server Cookie: {0}", Server_Cookie);

                    // Send back Server Cookie through the socket. 
                    msg = Encoding.ASCII.GetBytes(Server_Cookie);
                    bytesSent = sender.Send(msg);

                    // Generate 64bits Cookie
                    string Cookie = GenerateRandomBits(64);

                    Console.WriteLine("Cookie: {0}", Cookie);

                    // Send Cookie through the socket. 
                    msg = Encoding.ASCII.GetBytes(Cookie);
                    bytesSent = sender.Send(msg);
                    System.Threading.Thread.Sleep(50);

                    // Send supported suites to server
                    msg = Encoding.ASCII.GetBytes("MD5");
                    bytesSent = sender.Send(msg);
                    System.Threading.Thread.Sleep(50);

                    msg = Encoding.ASCII.GetBytes("SHA256");
                    bytesSent = sender.Send(msg);
                    System.Threading.Thread.Sleep(50);

                    msg = Encoding.ASCII.GetBytes("Blowfish");
                    bytesSent = sender.Send(msg);
                    System.Threading.Thread.Sleep(50);

                    msg = Encoding.ASCII.GetBytes("AES");
                    bytesSent = sender.Send(msg);
                    System.Threading.Thread.Sleep(50);

                    // Receive chosen suites
                    bytes = new byte[1024];
                    bytesRec = sender.Receive(bytes);
                    string suite1 = Encoding.ASCII.GetString(bytes, 0, bytesRec);
                    Console.WriteLine("Suite 1: {0}", suite1);
                    System.Threading.Thread.Sleep(50);
                    bytes = new byte[1024];
                    bytesRec = sender.Receive(bytes);
                    string suite2 = Encoding.ASCII.GetString(bytes, 0, bytesRec);
                    Console.WriteLine("Suite 2: {0}", suite2);
                    System.Threading.Thread.Sleep(150);

                    //Receive X.509 self-signed certificate
                    bytes = new byte[2048];
                    bytesRec = sender.Receive(bytes);
                    X509Certificate2 Certificate = new X509Certificate2(bytes);
                    //Display Certificate
                    Console.WriteLine(Certificate.ToString(true));

                    string ans;
                    //check certificate
                    do
                    {
                        Console.WriteLine("Do you accept this certificate?(Y,N): ");
                        ans = Console.ReadLine();
                    } while (ans!="Y"&&ans!="N"&& ans != "y" && ans != "n");

                    if (ans=="Y"||ans=="y")
                    {
                        Console.WriteLine("Certificate is valid!");

                        //Generate 128bit RN 
                        String RN = GenerateRandomBits(128);
                        Console.WriteLine("RN: {0}", RN);

                        SHA256 mySHA256 = SHA256Managed.Create();

                        //Cookie_Server | Cookie_Client | RN
                        String C_server_C_client_RN = GetSHA256Hash(mySHA256, Server_Cookie + Cookie + RN);

                        Console.WriteLine("SHA256: {0}", C_server_C_client_RN);

                        //Split SHA256(Cookie_Server | Cookie_Client | RN) in half to make key1 key2
                        string s_key1 = C_server_C_client_RN.Substring(0, (int)(C_server_C_client_RN.Length / 2));
                        string s_key2 = C_server_C_client_RN.Substring((int)(C_server_C_client_RN.Length / 2), (int)(C_server_C_client_RN.Length / 2));

                        Console.WriteLine("Key1: {0}", s_key1);
                        Console.WriteLine("Key2: {0}", s_key2);

                        byte[] key1 = Encoding.ASCII.GetBytes(s_key1);
                        byte[] key2 = Encoding.ASCII.GetBytes(s_key2);

                        //encrypt RN with server public key
                        RSACryptoServiceProvider RSACSP = (RSACryptoServiceProvider)Certificate.PublicKey.Key;
                        byte[] RN_S = Encoding.ASCII.GetBytes(RN);

                        msg = RSACSP.Encrypt(RN_S, false);
                        bytesSent = sender.Send(msg);
                        System.Threading.Thread.Sleep(50);

                        //generate HMAC(Suite1+Suite2)
                        HMACSHA256 hmac1 = new HMACSHA256(key2);
                        String hmac = GetHMACSHA256Hash(hmac1,suite1+suite2);

                        //send HMAC
                        msg = Encoding.ASCII.GetBytes(hmac);
                        bytesSent = sender.Send(msg);
                        System.Threading.Thread.Sleep(50);

                        //receive acknowledgement
                        bytes = new byte[1024];
                        bytesRec = sender.Receive(bytes);
                        string ack = DecryptString(Encoding.ASCII.GetString(bytes, 0, bytesRec), key1);

                        if (ack=="acknowledgement_done")
                        {
                            Console.WriteLine("Everything went good!");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Certificate is not valid!");
                    }

                    // Release the socket.  
                    sender.Shutdown(SocketShutdown.Both);  
                    sender.Close();  

                } catch (ArgumentNullException ane) {  
                    Console.WriteLine("ArgumentNullException : {0}",ane.ToString());  
                } catch (SocketException se) {  
                    Console.WriteLine("SocketException : {0}",se.ToString());  
                } catch (Exception e) {  
                    Console.WriteLine("Unexpected exception : {0}", e.ToString());  
                }  

            } catch (Exception e) {  
                Console.WriteLine( e.ToString());  
            }

            Console.WriteLine("\nPress ENTER to continue...");
            Console.Read();
        }  

        public static int Main(String[] args) {  
            StartClient();  
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
