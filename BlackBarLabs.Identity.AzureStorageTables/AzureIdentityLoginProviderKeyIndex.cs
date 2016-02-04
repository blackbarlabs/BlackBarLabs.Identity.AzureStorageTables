﻿using System;
using BlackBarLabs.Identity.AzureStorageTables.Extensions;
using Microsoft.WindowsAzure.Storage.Table;

namespace BlackBarLabs.Identity.AzureStorageTables
{
    public class AzureIdentityLoginProviderKeyIndex : TableEntity
    {
        public AzureIdentityLoginProviderKeyIndex(string userId, string loginProviderKey, string loginProvider)
        {
            PartitionKey = String.Format("{0}_{1}", loginProvider.Base64Encode(), loginProviderKey.Base64Encode());
            RowKey = "";
            UserId = userId;
        }
        
        // Add a parameterless constructor to resolve issue in AzureIdentityStore.cs FindAsync
        public AzureIdentityLoginProviderKeyIndex() { }

        public string GetLoginProvider()
        {
            return PartitionKey.Substring(0, PartitionKey.IndexOf('_')-1).Base64Decode();
        }

        public string GetLoginProviderKey()
        {
            return PartitionKey.Substring(PartitionKey.IndexOf('_')).Base64Decode();
        }

        public string UserId { get; set; }
    }
}
