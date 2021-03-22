/*
---
name: OAuth2.cs
description: CodeBit class for authentication using the OAuth2 protocol.
url: https://raw.githubusercontent.com/FileMeta/OAuth2CodeBit/master/OAuth2.cs
version: 1.0
keywords: CodeBit
dateModified: 2021-03-22
license: https://opensource.org/licenses/BSD-3-Clause
# Metadata in MicroYaml format. See http://filemeta.org/CodeBit.html
...
*/

/*
=== BSD 3 Clause License ===
https://opensource.org/licenses/BSD-3-Clause

Copyright 2021 Brandt Redd

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Net;

/* Implement Notes
This version was based on OAuth for Google but updated to work with Microsoft and then with
FaceBook. It still requires re-testing on Google and Microsoft. With some tweaks and testing
it should work with any OAuth 2.0 service.
*/

/* Facebook Info:

Register your application client in the Facebook APP console at: https://developers.facebook.com/apps.
Retrieve your App ID, and App Secret. These correspond to the OAuth clienId and clientSecret
Configure the "Login" application and set the callback URL to https://localhost:6502/

*/

/* Microsoft Info:
When registering Microsoft applications, you must register the following redirect URI https://localhost:6502/
 
Microsoft Graph OAuth: https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth 
OneDrive Special Folders: https://docs.microsoft.com/en-us/onedrive/developer/rest-api/resources/specialfolder
 
You can use Integrated Windows Authentication with the Microsoft Identity Platform v2.0
when running on Windows. This implementation does NOT do that. It's in that mode that you use
the default redirect URL of https://login.microsoftonline.com/common/oauth2/nativeclient

*/

namespace CodeBit
{
    // Using OAuth obtain an application bearer token
    class OAuth2
    {
        const string c_microsoftAuthorizationEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
        const string c_microsoftTokenExchangeEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

        const string c_googleAuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        const string c_googleTokenExchangeEndpoint = "https://www.googleapis.com/oauth2/v4/token";

        const string c_facebookAuthorizationEndpoint = "https://www.facebook.com/v10.0/dialog/oauth";
        const string c_facebookTokenExchangeEndpoint = "https://graph.facebook.com/oauth/access_token";


        public static OAuth2 CreateMicrosoftOauth(string clientId, string clientSecret)
        {
            return new OAuth2(c_microsoftAuthorizationEndpoint, c_microsoftTokenExchangeEndpoint,
                clientId, clientSecret);
        }

        public static OAuth2 CreateGoogleOauth(string clientId, string clientSecret)
        {
            return new OAuth2(c_googleAuthorizationEndpoint, c_googleTokenExchangeEndpoint,
                clientId, clientSecret);
        }

        public static OAuth2 CreateFacebookOauth(string clientId, string clientSecret)
        {
            return new OAuth2(c_facebookAuthorizationEndpoint, c_facebookTokenExchangeEndpoint,
                clientId, clientSecret);
        }

        const int c_localWebPortNumber = 6502;

        string m_authorizationEndpoint;
        string m_tokenExchangeEndpoint;

        string m_clientId;
        string m_clientSecret;

        public OAuth2(string authorizationEndpoint, string tokenExchangeEndpoint, string clientId, string clientSecret)
        {
            m_authorizationEndpoint = authorizationEndpoint;
            m_tokenExchangeEndpoint = tokenExchangeEndpoint;
            m_clientId = clientId;
            m_clientSecret = clientSecret;
        }

        public string LoginHint { get; set; }
        public string Error { get; private set; }

        public string Access_Token { get; private set; }
        public string Id_Token { get; private set; }
        public string Refresh_Token { get; private set; }
        public int Expires_In { get; private set; }
        public string Token_Type { get; private set; }

        public bool Authorize(params string[] scopes)
        {
            return Authorize(string.Join(" ", scopes));
        }

        public bool Authorize(string scope = null)
        {
            // Clear any previous authorization
            Access_Token = null;
            Id_Token = null;
            Refresh_Token = null;
            Expires_In = 0;
            Token_Type = null;

            // Create a redirect Url to which the browser will go once the user has been authenticated.
            string redirectUrl = string.Format($"http://localhost:{c_localWebPortNumber}/", IPAddress.Loopback, GetUnusedPortNumber());
            Debug.WriteLine("Redirect URL = " + redirectUrl);

            // Create an HttpListener to listen for requests on that redirect URL.
            var http = new HttpListener();
            http.Prefixes.Add(redirectUrl);
            Debug.WriteLine("HTTP Listening...");
            http.Start();

            // Create the OAuth 2.0 authorization request URL
            string authorizationRequestUrl = $"{m_authorizationEndpoint}?response_type=code&client_id={m_clientId}&redirect_uri={Uri.EscapeDataString(redirectUrl)}&response_mode=query";

            if (scope != null)
                authorizationRequestUrl += $"&scope={Uri.EscapeDataString(scope)}";

            if (!string.IsNullOrEmpty(LoginHint))
            {
                authorizationRequestUrl = string.Concat(authorizationRequestUrl, "&login_hint=", System.Uri.EscapeUriString(LoginHint));
            }

            // Open request in the browser.
            Process.Start(authorizationRequestUrl);

            // Wait for the OAuth authorization response.
            var context = http.GetContext();

            // Send an HTTP response to the browser.
            {
                var response = context.Response;
                string responseString = string.Format("<html><head></head><body>Application has been authorized. You may close this window or tab.</body></html>");
                var buffer = Encoding.UTF8.GetBytes(responseString);
                response.ContentLength64 = buffer.Length;
                var responseOutput = response.OutputStream;
                Task responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
                {
                    responseOutput.Close();
                    http.Stop();
                    Debug.WriteLine("HTTP server stopped.");
                });
            }

            // Checks for errors.
            if (context.Request.QueryString.Get("error") != null)
            {
                Error = context.Request.QueryString.Get("error");
                return false;
            }

            var code = context.Request.QueryString.Get("code");
            if (string.IsNullOrEmpty(code))
            {
                Error = "Malformed authorization response.";
                return false;
            }

            // Exchange the code for tokens
            string exchangeUrl = $"code={code}&client_id={m_clientId}&scope={scope}&redirect_uri={redirectUrl}&grant_type=authorization_code";
            if (!string.IsNullOrEmpty(m_clientSecret))
                exchangeUrl += $"&client_secret={m_clientSecret}";
            return ExchangeForTokens(string.Format("code={0}&client_id={1}&client_secret={2}&scope={3}&redirect_uri={4}&grant_type=authorization_code",
                code, m_clientId, m_clientSecret, scope, redirectUrl));
        }

        public bool Refresh(string refreshToken)
        {
            Refresh_Token = refreshToken;
            return ExchangeForTokens(string.Format("refresh_token={0}&client_id={1}&client_secret={2}&grant_type=refresh_token",
                refreshToken, m_clientId, m_clientSecret));
        }

        private bool ExchangeForTokens(string requestString)
        {
            HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(m_tokenExchangeEndpoint);
            tokenRequest.Method = "POST";
            tokenRequest.ContentType = "application/x-www-form-urlencoded";
            tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            byte[] bodyBytes = Encoding.ASCII.GetBytes(requestString);
            tokenRequest.ContentLength = bodyBytes.Length;
            using (var stream = tokenRequest.GetRequestStream())
            {
                stream.Write(bodyBytes, 0, bodyBytes.Length);
            }

            try
            {
                WebResponse response = tokenRequest.GetResponse();
                using (var reader = new OAuthJsonReader(response.GetResponseStream()))
                {
                    while (reader.Read())
                    {
                        switch (reader.Name)
                        {
                            case "access_token":
                                Access_Token = reader.Value;
                                break;

                            case "id_token":
                                Id_Token = reader.Value;
                                break;

                            case "refresh_token":
                                Refresh_Token = reader.Value;
                                break;

                            case "expires_in":
                                {
                                    int val;
                                    int.TryParse(reader.Value, out val);
                                    Expires_In = val;
                                }
                                break;

                            case "token_type":
                                Token_Type = reader.Value;
                                break;
                        }
                    }
                }
            }
            catch (WebException ex)
            {
                string error = "Error converting OAuth Token";
                var response = ex.Response as HttpWebResponse;
                if (response != null)
                {
                    string errTxt = string.Empty;
                    using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                    {
                        errTxt = reader.ReadToEnd();
                    }

                    error = string.Format("Error converting OAuth Token: HTTP {0}: {1}", response.StatusCode, errTxt);
                }
                Error = error;
                return false;
            }

            return true;
        }


        #region Private Helper Functions

        private static int GetUnusedPortNumber()
        {
            int port = 0;
            using (var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp))
            {
                IPEndPoint endPoint = new IPEndPoint(IPAddress.Loopback, 0);
                socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                port = ((IPEndPoint)socket.LocalEndPoint).Port;
            }
            return port;
        }

        #endregion
    }

    /// <summary>
    /// A simple JSON reader class used by OAuth2 but available for other uses
    /// </summary>
    class OAuthJsonReader : IDisposable
    {
        Stream m_stream;
        System.Xml.XmlReader m_reader;

        public static OAuthJsonReader Open(string filename)
        {
            return new OAuthJsonReader(new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read));
        }

        public OAuthJsonReader(Stream stream)
        {
            m_stream = stream;
            m_reader = System.Runtime.Serialization.Json.JsonReaderWriterFactory.CreateJsonReader(stream, Encoding.UTF8, new System.Xml.XmlDictionaryReaderQuotas(), null);
        }

        public string Name { get; private set; }
        public string Value { get; private set; }

        public bool Read()
        {
            while (m_reader.Read())
            {
                if (m_reader.NodeType == System.Xml.XmlNodeType.Element && !m_reader.IsEmptyElement)
                {
                    Name = m_reader.Name;
                }
                else if (m_reader.NodeType == System.Xml.XmlNodeType.EndElement)
                {
                    Name = null;
                }
                else if (m_reader.NodeType == System.Xml.XmlNodeType.Text && Name != null)
                {
                    Value = m_reader.Value;
                    return true;
                }
            }
            return false;
        }

        public void Dispose()
        {
            if (m_reader != null)
            {
                m_reader.Dispose();
            }
            if (m_stream != null)
            {
                m_stream.Dispose();
                m_stream = null;
            }
        }
    }

}
