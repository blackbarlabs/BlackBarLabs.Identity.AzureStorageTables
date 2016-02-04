using System;
using BlackBarLabs.Identity.AzureStorageTables.Extensions;
using Microsoft.AspNet.Identity;
using Microsoft.WindowsAzure.Storage.Table;

namespace BlackBarLabs.Identity.AzureStorageTables
{
    public class AzureIdentityRole : TableEntity, IRole
    {
        public AzureIdentityRole()
        {

        }

        public AzureIdentityRole(string userId, string name)
        {
            Id = Guid.NewGuid().ToString();
            UserId = userId;
            Name = name;
            SetPartitionAndRowKey();
        }

        public void SetPartitionAndRowKey()
        {
            PartitionKey = UserId;
            RowKey = Name.Base64Encode();
        }

        public string UserId { get; set; }
        public string Id { get; set; }
        public string Name { get; set; }
    }
}
