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
    public class ProductProperties
    {
        public string displayName { get; set; }
        public string description { get; set; }
        public object terms { get; set; }
        public bool subscriptionRequired { get; set; }
        public bool approvalRequired { get; set; }
        public int subscriptionsLimit { get; set; }
        public string state { get; set; }
    }

    public class Product
    {
        public string id { get; set; }
        public string type { get; set; }
        public string name { get; set; }
        public ProductProperties properties { get; set; }
    }


}
