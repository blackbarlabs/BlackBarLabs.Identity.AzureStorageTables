using Microsoft.WindowsAzure.Storage.Table;

namespace BlackBarLabs.Identity.AzureStorageTables
{
    public class AzureIdentityLogin : TableEntity
    {
        public AzureIdentityLogin()
        {
            
        }

        public AzureIdentityLogin(string userId, string loginProvider, string providerKey)
        {
            UserId = userId;
            LoginProvider = loginProvider;
            ProviderKey = providerKey;

            SetPartitionAndRowKey();
        }

        public void SetPartitionAndRowKey()
        {
            PartitionKey = UserId;
            RowKey = "";
        }

        public string LoginProvider { get; set; }

        public string ProviderKey { get; set; }

        public string UserId { get; set; }
    }
}
