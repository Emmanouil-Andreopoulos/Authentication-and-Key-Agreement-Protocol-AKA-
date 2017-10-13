using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

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
    }
}
