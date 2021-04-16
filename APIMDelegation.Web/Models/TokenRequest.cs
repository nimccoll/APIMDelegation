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
using System;

namespace APIMDelegation.Web.Models
{
    // TokenRequest myDeserializedClass = JsonConvert.DeserializeObject<TokenRequest>(myJsonResponse); 
    public class Properties
    {
        public string keyType { get; set; }
        public DateTime expiry { get; set; }
    }

    public class TokenRequest
    {
        public Properties properties { get; set; }
    }
}
