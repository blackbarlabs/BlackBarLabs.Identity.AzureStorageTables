using Microsoft.WindowsAzure.Storage.Table;

namespace BlackBarLabs.Identity.AzureStorageTables
{
    public class AzureIdentityEmailIndex : TableEntity
    {
        public AzureIdentityEmailIndex()
        {
            
        }

        public AzureIdentityEmailIndex(string base64EncodedEmail, string userId)
        {
            PartitionKey = base64EncodedEmail;
            RowKey = "";
            UserId = userId;
        }

        public string UserId { get; set; }
    }
}
