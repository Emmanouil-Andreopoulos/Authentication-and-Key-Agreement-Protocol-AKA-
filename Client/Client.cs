using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

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
    }
}
