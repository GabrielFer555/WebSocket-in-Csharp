using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace WebSocket
{
    public class Program
    {
        static void Main(string[] args)
        {
            string ipAddress = "127.0.0.1";
            int port = 8080;
            TcpListener server = new(IPAddress.Parse(ipAddress), port);

            server.Start();
            Console.WriteLine($"Server started running on {ipAddress}:{port}, waiting for connection...");

            TcpClient client = server.AcceptTcpClient();
            

            NetworkStream stream = client.GetStream();

            while (true)
            {
                // Wait until data is available to read
                while (!stream.DataAvailable) ;

                byte[] bytes = new byte[client.Available];
                stream.Read(bytes, 0, bytes.Length);

                string data = Encoding.UTF8.GetString(bytes);

                Console.WriteLine($"Received data: {BitConverter.ToString(bytes)}");

                if (Regex.IsMatch(data, "^GET", RegexOptions.IgnoreCase))
                {
                    const string eol = "\r\n";

                    // Calculate WebSocket Accept key
                    string key = new Regex("Sec-WebSocket-Key: (.*)").Match(data).Groups[1].Value.Trim();
                    string acceptKey = Convert.ToBase64String(
                        SHA1.Create().ComputeHash(
                            Encoding.UTF8.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                        )
                    );

                    // Send WebSocket handshake response
                    byte[] response = Encoding.UTF8.GetBytes(
                        "HTTP/1.1 101 Switching Protocols" + eol +
                        "Connection: Upgrade" + eol +
                        "Upgrade: websocket" + eol +
                        "Sec-WebSocket-Accept: " + acceptKey + eol +
                        eol
                    );
                    stream.Write(response, 0, response.Length);
                }
                else
                {
                    // WebSocket frame processing
                    bool fin = (bytes[0] & 0b10000000) != 0;
                    bool mask = (bytes[1] & 0b10000000) != 0;
                    int opcode = bytes[0] & 0b00001111; // Expecting 1 - text message

                    ulong msglen = bytes[1] & (ulong)0b01111111;
                    ulong offset = 2;

                    if (msglen == 126)
                    {
                        // Two-byte length field
                        msglen = BitConverter.ToUInt16(new byte[] { bytes[3], bytes[2] }, 0);
                        offset = 4;
                    }
                    else if (msglen == 127)
                    {
                        // Eight-byte length field
                        msglen = BitConverter.ToUInt64(new byte[] { bytes[9], bytes[8], bytes[7], bytes[6], bytes[5], bytes[4], bytes[3], bytes[2] }, 0);
                        offset = 10;
                    }

                    if (msglen == 0)
                    {
                        Console.WriteLine("Message length is 0");
                    }
                    else if (mask)
                    {
                        byte[] decoded = new byte[msglen];
                        byte[] masks = new byte[4]
                        {
                            bytes[offset],
                            bytes[offset + 1],
                            bytes[offset + 2],
                            bytes[offset + 3]
                        };
                        offset += 4;

                        for (ulong i = 0; i < msglen; ++i)
                        {
                            decoded[i] = (byte)(bytes[offset + i] ^ masks[i % 4]);
                        }

                        string text = Encoding.UTF8.GetString(decoded);
                        Console.WriteLine($"Received message: {text}");
                    }
                    else
                    {
                        Console.WriteLine("Mask bit not set");
                    }

                    Console.WriteLine();
                }
            }
        }
    }
}
