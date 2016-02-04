using Microsoft.WindowsAzure.Storage.Table;

namespace BlackBarLabs.Identity.AzureStorageTables
{
    public class AzureIdentityIdIndex : TableEntity
    {
        public AzureIdentityIdIndex()
        {
            
        }

        public AzureIdentityIdIndex(string base64UserName, string userId)
        {
            PartitionKey = base64UserName;
            RowKey = base64UserName;
            UserId = userId;
        }

        public string UserId { get; set; }
    }
}
