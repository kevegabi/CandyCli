using System.Text;
using System.Text.Json;
using System.Diagnostics;


namespace CandyCli
{
    /// <summary>
    /// Decoder for the encrypted response from the Candy appliance. It uses a brute-force approach to find the correct 16-character key, which is composed of alphanumeric characters. The decryption is done by XORing the encrypted bytes with the candidate key bytes, and it checks if the decrypted output is valid JSON.
    /// </summary>
    public class CandyDecoder
    {
        private readonly byte[] _encryptedBytes;
        private const int KeyLen = 16;
        private static readonly string KeyCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        private static readonly HashSet<byte> DecryptedCharsetBytes = Enumerable.Range(32, 95)
            .Concat(new int[] { 9, 10, 13 }).Select(i => (byte)i).ToHashSet();

        public CandyDecoder(string hexResponse)
        {
            string cleanHex = hexResponse.Trim().Replace(" ", "").Replace("\n", "").Replace("\r", "");
            _encryptedBytes = Convert.FromHexString(cleanHex);
        }

        /// <summary>
        /// Attempts to discover the correct decryption key by performing a parallel brute-force search over all
        /// possible key combinations.
        /// </summary>
        /// <remarks>This method uses parallel processing to accelerate the brute-force search. The
        /// operation may take significant time depending on the number of key candidates. The method returns as soon as
        /// a valid JSON is decrypted, or null if no valid key is found. The method updates the console UI periodically
        /// to indicate progress.</remarks>
        /// <returns>A tuple containing the discovered key as a string and the decrypted JSON text if a valid key is found;
        /// otherwise, null.</returns>
        public (string Key, string DecryptedJson)? BruteForceParallel()
        {
            var candidatesKeyBytes = new List<List<byte>>();
            for (int i = 0; i < KeyLen; i++)
            {
                var columnCandidates = GetCandidatesForKeyPosition(i).ToList();
                if (columnCandidates.Count == 0) return null;
                candidatesKeyBytes.Add(columnCandidates);
            }

            long totalCombinations = candidatesKeyBytes.Aggregate(1L, (acc, list) => acc * list.Count);

            Console.WriteLine($"Searching keys of {totalCombinations:N0} total combinations...");

            (string Key, string DecryptedJson)? foundResult = null;
            Stopwatch sw = Stopwatch.StartNew();

            Parallel.For(0, totalCombinations, (index, state) =>
            {
                byte[] currentKey = new byte[KeyLen];
                long tempIndex = index;

                for (int i = KeyLen - 1; i >= 0; i--)
                {
                    int charIndex = (int)(tempIndex % candidatesKeyBytes[i].Count);
                    currentKey[i] = candidatesKeyBytes[i][charIndex];
                    tempIndex /= candidatesKeyBytes[i].Count;
                }

                byte firstByte = (byte)(_encryptedBytes[0] ^ currentKey[0]);
                if (firstByte == 0x7B)
                {
                    byte[] decrypted = DecryptWithKey(currentKey);
                    string decryptedText = Encoding.UTF8.GetString(decrypted);

                    if (IsValidJson(decryptedText))
                    {
                        foundResult = (Encoding.UTF8.GetString(currentKey), decryptedText);
                        sw.Stop();
                        state.Stop();
                    }
                }
            });

            return foundResult;
        }

        /// <summary>
        /// Identifies all possible key byte values for a specified position in the key that, when used to decrypt the
        /// corresponding bytes in the encrypted data, produce valid characters according to the allowed decrypted
        /// character set.  
        /// </summary>
        /// <remarks>Use this method to determine which key bytes can be used at a particular position in
        /// the key without producing invalid decrypted characters. This is useful when iteratively constructing or
        /// analyzing possible keys for a cipher where only certain decrypted characters are allowed.</remarks>
        /// <param name="offset">The zero-based index of the key position to evaluate. Must be greater than or equal to 0 and less than the
        /// key length.</param>
        /// <returns>An enumerable collection of key byte values that are valid candidates for the specified key position. The
        /// collection may be empty if no candidates are found.</returns>
        private IEnumerable<byte> GetCandidatesForKeyPosition(int offset)
        {
            foreach (char c in KeyCharset)
            {
                byte k = (byte)c;
                bool valid = true;
                for (int i = offset; i < _encryptedBytes.Length; i += KeyLen)
                {
                    if (!DecryptedCharsetBytes.Contains((byte)(_encryptedBytes[i] ^ k)))
                    {
                        valid = false; break;
                    }
                }
                if (valid) yield return k;
            }
        }

        /// <summary>
        /// Decrypts the encrypted byte array using the specified key with a repeating XOR operation.
        /// </summary>
        /// <remarks>The decryption uses a repeating XOR pattern, where each byte of the encrypted data is
        /// XORed with the corresponding byte of the key, cycling through the key as needed. The caller is responsible
        /// for ensuring the key is appropriate for the encryption scheme used.</remarks>
        /// <param name="key">The key used to decrypt the encrypted bytes. The key must not be null or empty; its bytes are applied in a
        /// repeating sequence.</param>
        /// <returns>A byte array containing the decrypted data. The length of the returned array matches the length of the
        /// encrypted bytes.</returns>
        public byte[] DecryptWithKey(byte[] key)
        {
            byte[] result = new byte[_encryptedBytes.Length];
            for (int i = 0; i < _encryptedBytes.Length; i++)
                result[i] = (byte)(_encryptedBytes[i] ^ key[i % key.Length]);
            return result;
        }

        /// <summary>
        /// Determines whether the specified string contains valid JSON data.   
        /// </summary>
        /// <remarks>This method checks whether the input string can be parsed as JSON. It does not
        /// validate the semantic content of the JSON, only its syntactic correctness. If the input is null, the method
        /// will return false.</remarks>
        /// <param name="text">The JSON text to validate. Cannot be null.</param>
        /// <returns>true if the input string is valid JSON; otherwise, false.</returns>
        private static bool IsValidJson(string text)
        {
            try { using var doc = JsonDocument.Parse(text); return true; }
            catch { return false; }
        }
    }

    /// <summary>
    /// Provides methods for sending HTTP requests to a specified endpoint and retrieving the response as a string.
    /// </summary>
    /// <remarks>This class is intended for simple HTTP GET operations targeting endpoints constructed from
    /// the provided IP address, method name, and port. All methods are static and thread-safe. The class does not
    /// maintain any persistent connections or state.</remarks>
    public static class CandyHttpClient
    {
        /// <summary>
        /// Sends an HTTP GET request to the specified endpoint and asynchronously retrieves the response body as a
        /// string.
        /// </summary>
        /// <remarks>The request is sent to a URL constructed using the provided IP address and method
        /// name. If the server is unreachable or the request fails, the method returns an empty string instead of
        /// throwing an exception.</remarks>
        /// <param name="ip">The IP address of the target server to which the request is sent. Must be a valid IPv4 or IPv6 address.</param>
        /// <param name="method">The method name used to construct the endpoint path. Determines which resource is accessed on the server.</param>
        /// <param name="port">The port number to use for the HTTP request. Defaults to 80 if not specified.</param>
        /// <returns>A string containing the response body from the server. Returns an empty string if the request fails.</returns>
        public static async Task<string> GetResponseAsync(string ip, string method, string extraParams = "", int port = 80)
        {
            using var client = new HttpClient();
            try
            {
                string url = $"http://{ip}/http-{method}.json?encrypted=1"; // Ide írd a végpontot

                // GET kérés elküldése és a válasz beolvasása stringként
                string responseBody = await client.GetStringAsync(url);
                return responseBody;
            }
            catch (HttpRequestException e)
            {
                return "";
            }
        }
    }


    /// <summary>
    /// CandyCli - Easy to use .NET solution for Candy appliance (original idea: https://github.com/MelvinGr/CandySimplyFi-tool)
    /// 
    /// </summary>
    public static class Program
    {
        public static async Task Main(string[] args)
        {
            Console.WriteLine("Candy Simply-Fi Async Client - https://github.com/kevegabi/CandyCli");
            if (args.Length != 2 && args.Length != 3)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("candycli <ip> getkey - get the encryptionKey from the device, using bruteforce algorithm");
                Console.WriteLine("candycli <ip> decryptkey <encrypted-result> - get the encryptionKey from the device, using bruteforce algorithm");
                Console.WriteLine("candycli <ip> <key> <method> <extraPArams> - get status from device (method: read, write)");
                return;
            }

            switch (args[1])
            {
                case "getkey":
                    {
                        string ip = args[0];
                        var hex = await CandyHttpClient.GetResponseAsync(ip, "read");

                        if (hex.Length == 0)
                        {
                            Console.WriteLine("Error: No data returned");
                            return;
                        }

                        CandyDecoder decoder = new(hex);
                        var decrypted = decoder.BruteForceParallel();
                        Console.WriteLine(!decrypted.HasValue
                            ? "Key not found."
                            : $"Found key: {decrypted.Value.Key}\nDecrypted JSON:\n{decrypted.Value.DecryptedJson}");
                        break;
                    }
                case "decryptkey":
                    {
                        string ip = args[0];
                        string hex = args[2];
                        if (hex.Length == 0)
                        {
                            Console.WriteLine("Error: No data returned");
                            return;
                        }
                        CandyDecoder decoder = new(hex);
                        var decrypted = decoder.BruteForceParallel();
                        Console.WriteLine(!decrypted.HasValue
                            ? "Key not found."
                            : $"Found key: {decrypted.Value.Key}\nDecrypted JSON:\n{decrypted.Value.DecryptedJson}");
                        break;
                    }
                default:
                    {
                        string ip = args[0];
                        string key = args[1];
                        string method = args[2];
                        string extraParams = args[3];

                        string encryptedResult = await CandyHttpClient.GetResponseAsync(ip, method, extraParams);
                        CandyDecoder decoder = new(encryptedResult);
                        var result = decoder.DecryptWithKey(Encoding.UTF8.GetBytes(key));
                        Console.WriteLine(Encoding.UTF8.GetString(result));
                        break;
                    }
            }
        }
    }
}