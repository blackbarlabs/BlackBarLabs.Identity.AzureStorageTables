using System.Collections.Generic;
using System.Threading.Tasks;
using BlackBarLabs.Identity.AzureStorageTables.Extensions;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;

namespace BlackBarLabs.Identity.AzureStorageTables
{
    /// <summary>
    /// This class will build indexes for an existing table user store. It's really just there to patch a pre v0.3.0.0 release.
    /// </summary>
    public class AzureIdentityIndexBuilder
    {
        private readonly CloudTable _userTable;
        private readonly CloudTable _userIndexTable;

        public AzureIdentityIndexBuilder(CloudStorageAccount storageAccount) : this(storageAccount, "users", "userIndexItems")
        {
            
        }

        public AzureIdentityIndexBuilder(CloudStorageAccount storageAccount, string userTableName, string userIndexTableName)
        {
            CloudTableClient tableClient = storageAccount.CreateCloudTableClient();
            _userTable = tableClient.GetTableReference(userTableName);
            _userIndexTable = tableClient.GetTableReference(userIndexTableName);

            _userIndexTable.CreateIfNotExists();
        }

        public async Task BuildIndexes()
        {
            TableQuery<AzureIdentity> query = new TableQuery<AzureIdentity>();
            TableQuerySegment<AzureIdentity> querySegment = null;
            List<Task> insertOperation = new List<Task>();

            while (querySegment == null || querySegment.ContinuationToken != null)
            {
                querySegment = await _userTable.ExecuteQuerySegmentedAsync(query, querySegment != null ? querySegment.ContinuationToken : null);
                foreach (AzureIdentity tableUser in querySegment.Results)
                {
                    AzureIdentityIdIndex indexItem = new AzureIdentityIdIndex(tableUser.UserName.Base64Encode(), tableUser.Id);
                    insertOperation.Add(_userIndexTable.ExecuteAsync(TableOperation.InsertOrReplace(indexItem)));
                    if (insertOperation.Count > 100)
                    {
                        await Task.WhenAll(insertOperation);
                        insertOperation.Clear();
                    }
                }
                if (insertOperation.Count > 0)
                {
                    await Task.WhenAll(insertOperation);
                    insertOperation.Clear();
                }
            }
        }
    }
}
