using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using CodeBit;

/* Unit test for OAuth */

namespace OAuth2CodeBit
{
    class Program
    {
        const string c_configFilename = "local-secrets.json";

        static void Main(string[] args)
        {
            var config = new Configuration(c_configFilename);

            var oauth = OAuth2.CreateFacebookOauth(config.FacebookClientId, config.FacebookClientSecret);

            var res = oauth.Authorize();
            if (!res)
            {
                Console.WriteLine($"Failed: {oauth.Error}");
            }
            else
            {
                Console.WriteLine($"Authorization Succeeded.");
            }

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }
    }

    class Configuration
    {
        public Configuration(string filename)
        {
            // Look up the tree to find the secrets file
            string folder = Environment.CurrentDirectory;
            string filePath;
            for (; ; )
            {
                filePath = Path.Combine(folder, filename);
                if (File.Exists(filePath)) break;

                folder = Path.GetDirectoryName(folder);
                if (string.IsNullOrEmpty(folder))
                {
                    throw new ApplicationException($"Failed to find configuration file '{filename}'. Must exist in the executable directory or a parent thereof.");
                }
            }

            // Read the configuration from JSON
            using (var reader = OAuthJsonReader.Open(filePath))
            {
                while (reader.Read())
                {
                    switch (reader.Name)
                    {
                        case "facebookClientId":
                            FacebookClientId = reader.Value;
                            break;

                        case "facebookClientSecret":
                            FacebookClientSecret = reader.Value;
                            break;
                    }
                }
            }
        }

        public string FacebookClientId { get; private set; }
        public string FacebookClientSecret { get; private set; }

    }
}
