using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using BlackBarLabs.Identity.AzureStorageTables.Extensions;
using Microsoft.AspNet.Identity;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;

namespace BlackBarLabs.Identity.AzureStorageTables
{
    public class AzureIdentityStore<T> : 
        IUserLoginStore<T>,
        IUserClaimStore<T>,
        IUserRoleStore<T>,
        IUserPasswordStore<T>,
        IUserSecurityStampStore<T>,
        IUserStore<T>,
        // 2.0 interfaces
        //IQueryableUserStore<T>,
        IUserEmailStore<T>,
        IUserPhoneNumberStore<T>,
        IUserTwoFactorStore<T, string>,
        IUserLockoutStore<T, string>,
        IDisposable where T : AzureIdentity, new()
    {
        private readonly DateTimeOffset _minTableStoreDate = new DateTimeOffset(1753, 1, 1, 0, 0, 1, TimeSpan.FromHours(0));

        private readonly CloudTable _userTable;
        private readonly CloudTable _loginTable;
        private readonly CloudTable _claimsTable;
        private readonly CloudTable _rolesTable;
        private readonly CloudTable _userIndexTable;
        private readonly CloudTable _loginProviderKeyIndexTable;
        private readonly CloudTable _userEmailIndexTable;

        public AzureIdentityStore(CloudStorageAccount storageAccount,
            bool createIfNotExist,
            string userTableName,
            string userIndexTableName,
            string loginsTableName,
            string loginProviderKeyIndexTableName,
            string claimsTable,
            string rolesTable,
            string userEmailIndexTableName)
        {
            CloudTableClient tableClient = storageAccount.CreateCloudTableClient();
            
            _userTable = tableClient.GetTableReference(userTableName);
            _loginTable = tableClient.GetTableReference(loginsTableName);
            _claimsTable = tableClient.GetTableReference(claimsTable);
            _rolesTable = tableClient.GetTableReference(rolesTable);
            _userIndexTable = tableClient.GetTableReference(userIndexTableName);
            _loginProviderKeyIndexTable = tableClient.GetTableReference(loginProviderKeyIndexTableName);
            _userEmailIndexTable = tableClient.GetTableReference(userEmailIndexTableName);

            if (createIfNotExist)
            {
                _userTable.CreateIfNotExists();
                _loginTable.CreateIfNotExists();
                _claimsTable.CreateIfNotExists();
                _rolesTable.CreateIfNotExists();
                _userIndexTable.CreateIfNotExists();
                _loginProviderKeyIndexTable.CreateIfNotExists();
                _userEmailIndexTable.CreateIfNotExists();
            }
        }

        public AzureIdentityStore(CloudStorageAccount storageAccount) : this(storageAccount, true)
        {
            
        }

        public AzureIdentityStore(CloudStorageAccount storageAccount, bool createIfNotExist) :
            this(storageAccount, createIfNotExist, "users", "userIndexItems", "logins", "loginProviderKeyIndex", "claims", "roles", "userEmailIndex")
        {
            
        }

        public AzureIdentityStore(string connectionString) : this(CloudStorageAccount.Parse(connectionString))
        {
            
        }

        public void Dispose()
        {
            
        }

        public async Task CreateAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            user.SetPartitionAndRowKey();
            AzureIdentityIdIndex indexItem = new AzureIdentityIdIndex(user.UserName.Base64Encode(), user.Id);
            TableOperation indexOperation = TableOperation.Insert(indexItem);

            try
            {
                await _userIndexTable.ExecuteAsync(indexOperation);
            }
            catch (StorageException ex)
            {
                if (ex.RequestInformation.HttpStatusCode == 409)
                {
                    throw new DuplicateUsernameException();
                }
                throw;
            }

            if (!String.IsNullOrWhiteSpace(user.Email))
            {
                AzureIdentityEmailIndex emailIndexItem = new AzureIdentityEmailIndex(user.Email.Base64Encode(), user.Id);
                TableOperation emailIndexOperation = TableOperation.Insert(emailIndexItem);
                try
                {
                    await _userEmailIndexTable.ExecuteAsync(emailIndexOperation);
                }
                catch (StorageException ex)
                {
                    try
                    {
                        indexItem.ETag = "*";
                        TableOperation deleteOperation = TableOperation.Delete(indexItem);
                        _userIndexTable.ExecuteAsync(deleteOperation).Wait();
                    }
                    catch (Exception)
                    {
                        // if we can't delete the index item throw out the exception below
                    }
                    

                    if (ex.RequestInformation.HttpStatusCode == 409)
                    {
                        throw new DuplicateEmailException();
                    }
                    throw;
                }
            }
            
            try
            {
                if (user.LockoutEndDate < _minTableStoreDate)
                {
                    user.LockoutEndDate = _minTableStoreDate;
                }
                TableOperation operation = TableOperation.InsertOrReplace(user);
                await _userTable.ExecuteAsync(operation);

                if (user.Logins.Any())
                {
                    TableBatchOperation batch = new TableBatchOperation();
                    List<AzureIdentityLoginProviderKeyIndex> loginIndexItems = new List<AzureIdentityLoginProviderKeyIndex>();
                    foreach (AzureIdentityLogin login in user.Logins)
                    {
                        login.UserId = user.Id;
                        login.SetPartitionAndRowKey();
                        batch.InsertOrReplace(login);

                        AzureIdentityLoginProviderKeyIndex loginIndexItem = new AzureIdentityLoginProviderKeyIndex(user.Id, login.ProviderKey, login.LoginProvider);
                        loginIndexItems.Add(loginIndexItem);
                    }
                    await _loginTable.ExecuteBatchAsync(batch);
                    // can't batch the index items as different primary keys
                    foreach (AzureIdentityLoginProviderKeyIndex loginIndexItem in loginIndexItems)
                    {
                        await _loginProviderKeyIndexTable.ExecuteAsync(TableOperation.InsertOrReplace(loginIndexItem));
                    }
                }
            }
            catch (Exception)
            {
                // attempt to delete the index item - needs work
                indexItem.ETag = "*";
                TableOperation deleteOperation = TableOperation.Delete(indexItem);
                _userIndexTable.ExecuteAsync(deleteOperation).Wait();
                throw;
            }
        }

        public async Task UpdateAsync(T user)
        {
            // assumption here is that a username can't change (if it did we'd need to fix the index)
            if (user == null) throw new ArgumentNullException("user");
            user.ETag = "*";
            TableOperation operation = TableOperation.Merge(user);
            if (user.LockoutEndDate < _minTableStoreDate)
            {
                user.LockoutEndDate = _minTableStoreDate;
            }
            await _userTable.ExecuteAsync(operation);
        }

        public async Task DeleteAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            TableOperation operation = TableOperation.Delete(user);
            user.ETag = "*";
            await _userTable.ExecuteAsync(operation);

            //Clean up
            try 
            { 
                await RemoveFromAllRolesAsync(user); 
            }
                // ReSharper disable once EmptyGeneralCatchClause
            catch { }

            try
            {
                await RemoveAllClaimsAsync(user);
            }
                // ReSharper disable once EmptyGeneralCatchClause
            catch { }

            try
            {
                await RemoveAllLoginsAsync(user);
            }
                // ReSharper disable once EmptyGeneralCatchClause
            catch { }

            try
            {
                await RemoveIndices(user);
            }
                // ReSharper disable once EmptyGeneralCatchClause
            catch { }

        }

        private async Task RemoveIndices(T user)
        {
            AzureIdentityIdIndex userIdIndex = new AzureIdentityIdIndex(user.UserName.Base64Encode(),user.Id);
            userIdIndex.ETag = "*";
            AzureIdentityEmailIndex emailIndex = new AzureIdentityEmailIndex(user.Email.Base64Encode(),user.Id);
            emailIndex.ETag = "*";

            Task t1 = _userIndexTable.ExecuteAsync(TableOperation.Delete(userIdIndex));
            Task t2 = _userEmailIndexTable.ExecuteAsync(TableOperation.Delete(emailIndex));

            await Task.WhenAll(t1, t2);
        }

        public Task<T> FindByIdAsync(string userId)
        {
            if (String.IsNullOrWhiteSpace(userId)) throw new ArgumentNullException("userId");
            return Task.Factory.StartNew(() =>
            {
                TableQuery<T> query =
                    new TableQuery<T>().Where(
                        TableQuery.GenerateFilterCondition("PartitionKey",
                            QueryComparisons.Equal, userId)).Take(1);
                IEnumerable<T> results = _userTable.ExecuteQuery(query);
                T result = results.SingleOrDefault();
                if (result != null)
                {
                    result.LazyLoginEvaluator = () =>
                    {
                        Task<IList<UserLoginInfo>> loginInfoTask = GetLoginsAsync(result);
                        loginInfoTask.Wait();
                        IList<UserLoginInfo> loginInfo = loginInfoTask.Result;
                        return loginInfo.Select(x => new AzureIdentityLogin(result.Id, x.LoginProvider, x.ProviderKey));
                    };
                    result.LazyClaimsEvaluator = () =>
                    {
                        Task<IList<Claim>> claimTask = GetClaimsAsync(result);
                        claimTask.Wait();
                        IList<Claim> loginInfo = claimTask.Result;
                        return loginInfo.Select(x => new AzureIdentityClaim(result.Id, x.Type, x.Value));
                    };
                    result.LazyRolesEvaluator = () =>
                    {
                        Task<IList<string>> roleTask = GetRolesAsync(result);
                        roleTask.Wait();
                        IList<string> roles = roleTask.Result;
                        return roles.Select(x => new AzureIdentityRole(result.Id, x));
                    };
                }
                
                return result;
            });
        }

        public Task<T> FindByNameAsync(string userName)
        {
            if (String.IsNullOrWhiteSpace(userName)) throw new ArgumentNullException("userName");
            return Task.Factory.StartNew(() =>
            {
                TableQuery<AzureIdentityIdIndex> indexQuery = new TableQuery<AzureIdentityIdIndex>().Where(
                    TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, userName.Base64Encode())).Take(1);
                IEnumerable<AzureIdentityIdIndex> indexResults = _userIndexTable.ExecuteQuery(indexQuery);
                AzureIdentityIdIndex indexItem = indexResults.SingleOrDefault();

                if (indexItem == null)
                {
                    return null;
                }

                TableQuery<T> query =
                    new TableQuery<T>().Where(
                        TableQuery.GenerateFilterCondition("PartitionKey",
                            QueryComparisons.Equal, indexItem.UserId)).Take(1);
                IEnumerable<T> results = _userTable.ExecuteQuery(query);
                return results.SingleOrDefault();
            });
        }

        public async Task AddLoginAsync(T user, UserLoginInfo loginInfo)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (loginInfo == null) throw new ArgumentNullException("loginInfo");

            var login = new AzureIdentityLogin(user.Id, loginInfo.LoginProvider, loginInfo.ProviderKey);
            var operation = TableOperation.Insert(login);
            await _loginTable.ExecuteAsync(operation);

            var loginIndexItem = new AzureIdentityLoginProviderKeyIndex(user.Id, login.ProviderKey, login.LoginProvider);
            await _loginProviderKeyIndexTable.ExecuteAsync(TableOperation.InsertOrReplace(loginIndexItem));
        }

        public async Task RemoveLoginAsync(T user, UserLoginInfo loginInfo)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (loginInfo == null) throw new ArgumentNullException("loginInfo");

            AzureIdentityLogin login = new AzureIdentityLogin(user.Id, loginInfo.LoginProvider, loginInfo.ProviderKey);
            login.ETag = "*";
            TableOperation operation = TableOperation.Delete(login);
            await _loginTable.ExecuteAsync(operation);

            AzureIdentityLoginProviderKeyIndex loginIndexItem = new AzureIdentityLoginProviderKeyIndex(user.Id, login.ProviderKey, login.LoginProvider);
            loginIndexItem.ETag = "*";
            TableOperation indexOperation = TableOperation.Delete(loginIndexItem);
            await _loginProviderKeyIndexTable.ExecuteAsync(indexOperation);
        }

        public async Task RemoveAllLoginsAsync(T user)
        {
            bool error = false;
            List<AzureIdentityLogin> Logins = new List<AzureIdentityLogin>();
            string partitionKeyQuery = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, user.Id);
            TableQuery<AzureIdentityLogin> query = new TableQuery<AzureIdentityLogin>().Where(partitionKeyQuery);
            TableQuerySegment<AzureIdentityLogin> querySegment = null;

            while (querySegment == null || querySegment.ContinuationToken != null)
            {
                querySegment = await _loginTable.ExecuteQuerySegmentedAsync(query, querySegment != null ? querySegment.ContinuationToken : null);
                Logins.AddRange(querySegment.Results);
            }

            TableBatchOperation batch = new TableBatchOperation();
            TableBatchOperation batchIndex = new TableBatchOperation();
            foreach (AzureIdentityLogin login in Logins)
            {
                login.ETag = "*"; //Delete even if it has changed
                batch.Add(TableOperation.Delete(login));
                AzureIdentityLoginProviderKeyIndex providerKeyIndex = new AzureIdentityLoginProviderKeyIndex(user.Id, login.ProviderKey, login.LoginProvider);
                providerKeyIndex.ETag = "*";
                batchIndex.Add(TableOperation.Delete(providerKeyIndex));

                if (batch.Count >= 100 || batchIndex.Count >= 100)
                {
                    try
                    {
                        //Try executing as a batch
                        await _loginTable.ExecuteBatchAsync(batch);
                        batch.Clear();
                    }
                    catch { }

                    //If a batch wont work, try individually
                    foreach (TableOperation op in batch)
                    {
                        try
                        {
                            await _loginTable.ExecuteAsync(op);
                        }
                        catch
                        {
                            error = true;
                        }
                    }

                    //Delete the index individually becase of the partition keys
                    foreach (TableOperation op in batchIndex)
                    {
                        try
                        {
                            await _loginProviderKeyIndexTable.ExecuteAsync(op);
                        }
                        catch
                        {
                            error = true;
                        }
                    }

                    batch.Clear();
                    batchIndex.Clear();
                }

            }
            if (batch.Count > 0 || batchIndex.Count > 0)
            {
                try
                {
                    //Try executing as a batch
                    await _loginTable.ExecuteBatchAsync(batch);
                    batch.Clear();
                }
                    // ReSharper disable once EmptyGeneralCatchClause
                catch { }

                //If a batch wont work, try individually
                foreach (TableOperation op in batch)
                {
                    try
                    {
                        await _loginTable.ExecuteAsync(op);
                    }
                    catch
                    {
                        error = true;
                    }
                }

                //Delete the index individually becase of the partition keys
                foreach (TableOperation op in batchIndex)
                {
                    try
                    {
                        await _loginProviderKeyIndexTable.ExecuteAsync(op);
                    }
                    catch
                    {
                        error = true;
                    }
                }
            }

            if (error)
            {
                throw new Exception();
            }
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.Factory.StartNew(() =>
            {
                TableQuery<AzureIdentityLogin> query =
                    new TableQuery<AzureIdentityLogin>().Where(
                        TableQuery.GenerateFilterCondition("PartitionKey",
                            QueryComparisons.Equal, user.Id)).Take(1);
                IEnumerable<AzureIdentityLogin> results = _loginTable.ExecuteQuery(query);
                return (IList<UserLoginInfo>)results.Select(x => new UserLoginInfo(x.LoginProvider, x.ProviderKey)).ToList();
            });
        }

        public async Task<T> FindAsync(UserLoginInfo login)
        {
            if (login == null) throw new ArgumentNullException("login");

            AzureIdentityLoginProviderKeyIndex candidateIndex = new AzureIdentityLoginProviderKeyIndex("", login.ProviderKey, login.LoginProvider);
            TableResult loginProviderKeyIndexResult = await _loginProviderKeyIndexTable.ExecuteAsync(TableOperation.Retrieve<AzureIdentityLoginProviderKeyIndex>(candidateIndex.PartitionKey, ""));
            AzureIdentityLoginProviderKeyIndex indexItem = (AzureIdentityLoginProviderKeyIndex)loginProviderKeyIndexResult.Result;
            if (indexItem == null) return null;

            return await FindByIdAsync(indexItem.UserId);
        }

        public async Task<IList<Claim>> GetClaimsAsync(T user)
        {
            if (user == null) throw new ArgumentNullException();
            
            List<Claim> claims = new List<Claim>();
            string partitionKeyQuery = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, user.Id);
            TableQuery<AzureIdentityClaim> query = new TableQuery<AzureIdentityClaim>().Where(partitionKeyQuery);
            TableQuerySegment<AzureIdentityClaim> querySegment = null;

            while (querySegment == null || querySegment.ContinuationToken != null)
            {
                querySegment = await _claimsTable.ExecuteQuerySegmentedAsync(query, querySegment != null ? querySegment.ContinuationToken : null);
                claims.AddRange(querySegment.Results.Select(x => new Claim(x.ClaimType, x.ClaimValue)));
            }

            return claims;
        }

        public async Task AddClaimAsync(T user, Claim claim)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (claim == null) throw new ArgumentNullException("claim");
            AzureIdentityClaim tableUserClaim = new AzureIdentityClaim(user.Id, claim.Type, claim.Value);
            TableOperation operation = TableOperation.Insert(tableUserClaim);
            await _claimsTable.ExecuteAsync(operation);
        }

        public async Task RemoveClaimAsync(T user, Claim claim)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (claim == null) throw new ArgumentNullException("claim");
            AzureIdentityClaim tableUserClaim = new AzureIdentityClaim(user.Id, claim.Type, claim.Value);
            tableUserClaim.ETag = "*";
            TableOperation operation = TableOperation.Delete(tableUserClaim);
            await _claimsTable.ExecuteAsync(operation);
        }

        public async Task RemoveAllClaimsAsync(T user)
        {
            bool error = false;
            List<AzureIdentityClaim> claims = new List<AzureIdentityClaim>();
            string partitionKeyQuery = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, user.Id);
            TableQuery<AzureIdentityClaim> query = new TableQuery<AzureIdentityClaim>().Where(partitionKeyQuery);
            TableQuerySegment<AzureIdentityClaim> querySegment = null;

            while (querySegment == null || querySegment.ContinuationToken != null)
            {
                querySegment = await _claimsTable.ExecuteQuerySegmentedAsync(query, querySegment != null ? querySegment.ContinuationToken : null);
                claims.AddRange(querySegment.Results);
            }

            TableBatchOperation batch = new TableBatchOperation();
            foreach (AzureIdentityClaim claim in claims)
            {
                claim.ETag = "*"; //Delete even it has changed
                batch.Add(TableOperation.Delete(claim));
                if (batch.Count >= 100)
                {
                    try
                    {
                        //Try executing as a batch
                        await _claimsTable.ExecuteBatchAsync(batch);
                        batch.Clear();
                    }
                    catch {}


                    //If a batch wont work, try individually
                    foreach (TableOperation op in batch)
                    {
                        try
                        {
                            await _claimsTable.ExecuteAsync(op);
                        }
                        catch
                        {
                            error = true;
                        }
                    }

                    batch.Clear();
                }
            }
            if (batch.Count > 0)
            {
                try
                {
                    //Try executing as a batch
                    await _claimsTable.ExecuteBatchAsync(batch);
                    batch.Clear();
                }
                catch { }


                //If a batch wont work, try individually
                foreach (TableOperation op in batch)
                {
                    try
                    {
                        await _claimsTable.ExecuteAsync(op);
                    }
                    catch
                    {
                        error = true;
                    }
                }
            }

            if(error)
            {
                throw new Exception();
            }
        }

        public async Task AddToRoleAsync(T user, string role)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (String.IsNullOrWhiteSpace(role)) throw new ArgumentNullException("role");
            AzureIdentityRole tableUserRole = new AzureIdentityRole(user.Id, role);
            TableOperation operation = TableOperation.Insert(tableUserRole);
            await _rolesTable.ExecuteAsync(operation);
        }

        public async Task RemoveFromRoleAsync(T user, string role)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (String.IsNullOrWhiteSpace(role)) throw new ArgumentNullException("role");
            AzureIdentityRole tableUserRole = new AzureIdentityRole(user.Id, role);
            tableUserRole.ETag = "*";
            TableOperation operation = TableOperation.Delete(tableUserRole);
            await _rolesTable.ExecuteAsync(operation);
        }

        public async Task RemoveFromAllRolesAsync(T user)
        {
            bool error = false;
            List<AzureIdentityRole> roles = new List<AzureIdentityRole>();
            string partitionKeyQuery = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, user.Id);
            TableQuery<AzureIdentityRole> query = new TableQuery<AzureIdentityRole>().Where(partitionKeyQuery);
            TableQuerySegment<AzureIdentityRole> querySegment = null;

            while (querySegment == null || querySegment.ContinuationToken != null)
            {
                querySegment = await _rolesTable.ExecuteQuerySegmentedAsync(query, querySegment != null ? querySegment.ContinuationToken : null);
                roles.AddRange(querySegment.Results);
            }

            TableBatchOperation batch = new TableBatchOperation();
            foreach (AzureIdentityRole role in roles)
            {
                role.ETag = "*"; //Delete even if it has changed
                batch.Add(TableOperation.Delete(role));
                if (batch.Count >= 100)
                {
                    try
                    {
                        //Try executing as a batch
                        await _rolesTable.ExecuteBatchAsync(batch);
                        batch.Clear();
                    }
                    catch { }

                    //If a batch wont work, try individually
                    foreach (TableOperation op in batch)
                    {
                        try
                        {
                            await _rolesTable.ExecuteAsync(op);
                        }
                        catch
                        {
                            error = true;
                        }
                    }

                    batch.Clear();
                }
            }
            if (batch.Count > 0)
            {
                try
                {
                    //Try executing as a batch
                    await _rolesTable.ExecuteBatchAsync(batch);
                    batch.Clear();
                }
                catch { }

                //If a batch wont work, try individually
                foreach (TableOperation op in batch)
                {
                    try
                    {
                        await _rolesTable.ExecuteAsync(op);
                    }
                    catch
                    {
                        error = true;
                    }
                }
            }
            if(error)
            {
                throw new Exception();
            }
        }

        public async Task<IList<string>> GetRolesAsync(T user)
        {
            if (user == null) throw new ArgumentNullException();

            List<string> claims = new List<string>();
            string partitionKeyQuery = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, user.Id);
            TableQuery<AzureIdentityRole> query = new TableQuery<AzureIdentityRole>().Where(partitionKeyQuery);
            TableQuerySegment<AzureIdentityRole> querySegment = null;

            while (querySegment == null || querySegment.ContinuationToken != null)
            {
                querySegment = await _rolesTable.ExecuteQuerySegmentedAsync(query, querySegment != null ? querySegment.ContinuationToken : null);
                claims.AddRange(querySegment.Results.Select(x => x.Name));
            }

            return claims;
        }

        public async Task<bool> IsInRoleAsync(T user, string role)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (String.IsNullOrWhiteSpace(role)) throw new ArgumentNullException("role");
            TableOperation operation = TableOperation.Retrieve(user.Id, role);
            return (await _rolesTable.ExecuteAsync(operation)).Result != null;
        }

        public Task SetPasswordHashAsync(T user, string passwordHash)
        {
            if (user == null) throw new ArgumentNullException("user");
            // If you add and remove a password from a user (only way to do a non-authenticated reset)
            // then this will get set to null
            //if (String.IsNullOrWhiteSpace(passwordHash)) throw new ArgumentNullException("passwordHash");

            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetSecurityStampAsync(T user, string stamp)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (String.IsNullOrWhiteSpace(stamp)) throw new ArgumentNullException("stamp");

            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");

            return Task.FromResult(user.SecurityStamp);
        }

        #region 2.0 interface implemenation

        //public IQueryable<T> Users { get; private set; }

        public Task SetEmailAsync(T user, string email)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (String.IsNullOrWhiteSpace(email)) throw new ArgumentNullException("email");

            user.Email = email;
            return Task.FromResult(0);
        }

        public Task<string> GetEmailAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailConfirmedAsync(T user, bool confirmed)
        {
            if (user == null) throw new ArgumentNullException("user");
            
            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public async Task<T> FindByEmailAsync(string email)
        {
            if (String.IsNullOrWhiteSpace(email)) return null;

            TableOperation retrieveIndexOp = TableOperation.Retrieve<AzureIdentityEmailIndex>(email.Base64Encode(), "");
            TableResult indexResult = await _userEmailIndexTable.ExecuteAsync(retrieveIndexOp);
            if (indexResult.Result == null) return null;
            AzureIdentityEmailIndex userEmailIndex = (AzureIdentityEmailIndex)indexResult.Result;
            return await FindByIdAsync(userEmailIndex.UserId);
        }

        public Task SetPhoneNumberAsync(T user, string phoneNumber)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (String.IsNullOrWhiteSpace(phoneNumber)) throw new ArgumentNullException("phoneNumber");

            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(T user, bool confirmed)
        {
            if (user == null) throw new ArgumentNullException("user");
            
            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public Task SetTwoFactorEnabledAsync(T user, bool enabled)
        {
            if (user == null) throw new ArgumentNullException("user");

            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task<bool> GetTwoFactorEnabledAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(user.TwoFactorEnabled);
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(user.LockoutEndDate);
        }

        public Task SetLockoutEndDateAsync(T user, DateTimeOffset lockoutEnd)
        {
            if (user == null) throw new ArgumentNullException("user");
            if (lockoutEnd < _minTableStoreDate)
            {
                lockoutEnd = _minTableStoreDate;
            }
            user.LockoutEndDate = lockoutEnd;
            return Task.FromResult(0);
        }

        public Task<int> IncrementAccessFailedCountAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(T user)
        {
            if (user == null) throw new ArgumentNullException("user");
            return Task.FromResult(user.LockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(T user, bool enabled)
        {
            if (user == null) throw new ArgumentNullException("user");
            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        #endregion
    }
}
