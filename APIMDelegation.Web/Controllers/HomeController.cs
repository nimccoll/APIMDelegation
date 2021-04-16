//===============================================================================
// Microsoft FastTrack for Azure
// Azure API Management Sign In Sign Up Delegation Example
//===============================================================================
// Copyright © Microsoft Corporation.  All rights reserved.
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
// LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE.
//===============================================================================
using APIMDelegation.Web.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureADB2C.UI;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace APIMDelegation.Web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;
        private readonly IOptionsMonitor<AzureADB2COptions> _options;
        private readonly string _apimIdentifier;
        private readonly string _apimKey;
        private readonly string _apimUrl;
        private readonly string _delegationValidationKey;
        private HttpClient _httpClient;


        public HomeController(ILogger<HomeController> logger, IConfiguration configuration, IOptionsMonitor<AzureADB2COptions> AzureADB2COptions)
        {
            _logger = logger;
            _configuration = configuration;
            _options = AzureADB2COptions;
            _apimIdentifier = _configuration.GetValue<string>("apimIdentitifer");
            _apimKey = _configuration.GetValue<string>("apimKey");
            _apimUrl = _configuration.GetValue<string>("apimUrl");
            _delegationValidationKey = _configuration.GetValue<string>("delegationValidationKey");
            _httpClient = new HttpClient();
        }

        [Authorize]
        public async Task<IActionResult> Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                string operation = Request.Query["operation"];
                string returnUrl = Request.Query["returnUrl"];
                string salt = Request.Query["salt"];
                string sig = Request.Query["sig"];
                string emailAddress = string.Empty;
                string redirectUrl = string.Empty;

                if (operation == "SignOut")
                {
                    return RedirectToAction("SignOut");
                }
                else // SignIn or SignUp - handled by Azure AD B2C
                {
                    // Validate the signature from the developer portal request
                    bool isSignatureValid = false;
                    using (var encoder = new HMACSHA512(Convert.FromBase64String(_delegationValidationKey)))
                    {
                        string signature = Convert.ToBase64String(encoder.ComputeHash(Encoding.UTF8.GetBytes(salt + "\n" + returnUrl)));
                        isSignatureValid = sig == signature;
                    }
                    if (isSignatureValid)
                    {
                        // Get the user's email address
                        foreach (Claim claim in User.Claims)
                        {
                            if (claim.Type == "mail")
                            {
                                emailAddress = claim.Value.ToString();
                                break;
                            }
                        }

                        if (!string.IsNullOrEmpty(emailAddress))
                        {
                            // Lookup APIM user by email address
                            string accessToken = GenerateAccessToken();
                            User user = await GetUser(emailAddress, accessToken);
                            if (user == null)
                            {
                                // Unknown user
                            }

                            // Get APIM token
                            string sharedAccessToken = await GetSharedAccessToken(user.name, accessToken);
                            if (!string.IsNullOrEmpty(sharedAccessToken))
                            {
                                redirectUrl = $"{_configuration.GetValue<string>("developerPortalSSOUrl")}?token={HttpUtility.UrlEncode(sharedAccessToken)}&returnUrl={HttpUtility.UrlEncode(returnUrl)}";
                                return new RedirectResult(redirectUrl);
                            }
                            else
                            {
                                // Failed to retrieve token
                            }
                        }
                    }
                    else
                    {
                        // Invalid signature
                    }
                }
            }
            return View();
        }

        [HttpGet("{scheme?}")]
        public async Task<IActionResult> SignOut([FromRoute] string scheme)
        {
            scheme = scheme ?? AzureADB2CDefaults.AuthenticationScheme;
            var authenticated = await HttpContext.AuthenticateAsync(scheme);
            if (!authenticated.Succeeded)
            {
                return Challenge(scheme);
            }

            var options = _options.Get(scheme);

            // Sign the user out of Azure AD B2C and redirect back to the APIM developer portal
            var callbackUrl = _configuration.GetValue<string>("developerPortalSignoutUrl");
            return SignOut(
                new AuthenticationProperties { RedirectUri = callbackUrl },
                options.AllSchemes);
        }

        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }

        [Authorize]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private async Task<User> GetUser(string emailAddress, string accessToken)
        {
            // Retrieve the APIM user information via their email address via the APIM Management API
            User user = null;

            string url = $"{_apimUrl}/users?api-version=2019-12-01&$filter=email eq '{emailAddress}'";
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("SharedAccessSignature", accessToken);
            HttpResponseMessage response = await _httpClient.GetAsync(url);
            if (response.IsSuccessStatusCode)
            {
                string responseContent = await response.Content.ReadAsStringAsync();
                Users users = JsonConvert.DeserializeObject<Users>(responseContent);
                if (users.count == 1)
                {
                    user = users.value[0];
                }
            }
            else
            {
                string responseContent = await response.Content.ReadAsStringAsync();
            }

            return user;
        }

        private async Task<string> GetSharedAccessToken(string userId, string accessToken)
        {
            // Generate a shared access token for the current user via the APIM Management API
            string sharedAccessToken = string.Empty;
            string url = $"{_apimUrl}/users/{userId}/token?api-version=2019-12-01";
            TokenRequest tokenRequest = new TokenRequest();
            tokenRequest.properties = new Properties()
            {
                keyType = "primary",
                expiry = DateTime.Now.AddDays(10)
            };
            StringContent stringContent = new StringContent(JsonConvert.SerializeObject(tokenRequest), Encoding.UTF8, "application/json");
            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("SharedAccessSignature", accessToken);
            HttpResponseMessage response = await _httpClient.PostAsync(url, stringContent);
            if (response.IsSuccessStatusCode)
            {
                string responseContent = await response.Content.ReadAsStringAsync();
                TokenResponse tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(responseContent);
                sharedAccessToken = tokenResponse.value;
            }
            else
            {
                string responseContent = await response.Content.ReadAsStringAsync();
            }

            return sharedAccessToken;
        }

        private string GenerateAccessToken()
        {
            // Generate an access token for the APIM Management API using the API Key
            string accessToken = string.Empty;

            var expiry = DateTime.UtcNow.AddDays(10);
            using (HMACSHA512 encoder = new HMACSHA512(Encoding.UTF8.GetBytes(_apimKey)))
            {
                string dataToSign = _apimIdentifier + "\n" + expiry.ToString("O", CultureInfo.InvariantCulture);
                byte[] hash = encoder.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
                string signature = Convert.ToBase64String(hash);
                accessToken = string.Format("uid={0}&ex={1:o}&sn={2}", _apimIdentifier, expiry, signature);
            }

            return accessToken;
        }
    }
}
