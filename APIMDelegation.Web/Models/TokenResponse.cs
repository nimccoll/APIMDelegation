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
namespace APIMDelegation.Web.Models
{
    // TokenResponse myDeserializedClass = JsonConvert.DeserializeObject<TokenResponse>(myJsonResponse); 
    public class TokenResponse
    {
        public string value { get; set; }
    }
}
