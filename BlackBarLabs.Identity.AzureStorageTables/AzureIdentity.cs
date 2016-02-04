using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.WindowsAzure.Storage.Table;

namespace BlackBarLabs.Identity.AzureStorageTables
{
    public class AzureIdentity : TableEntity, IUser
    {
        public void SetPartitionAndRowKey()
        {
            PartitionKey = Id;
            RowKey = Id;
        }

        public string Id { get; set; }

        public string UserName { get; set; }

        public string PasswordHash { get; set; }

        public string SecurityStamp { get; set; }

        public string Email { get; set; }

        public bool EmailConfirmed { get; set; }

        public string PhoneNumber { get; set; }

        public bool PhoneNumberConfirmed { get; set; }

        public bool TwoFactorEnabled { get; set; }

        public DateTimeOffset LockoutEndDate { get; set; }

        public int AccessFailedCount { get; set; }

        public bool LockoutEnabled { get; set; }

        [NonSerializedTableStore]
        internal Func<IEnumerable<AzureIdentityRole>> LazyRolesEvaluator { get; set; }

        private List<AzureIdentityRole> _roles;
        [NonSerializedTableStore]
        public ICollection<AzureIdentityRole> Roles
        {
            get
            {
                if (_roles == null)
                {
                    if (LazyRolesEvaluator != null)
                    {
                        _roles = new List<AzureIdentityRole>(LazyRolesEvaluator());
                    }
                    else
                    {
                        _roles = new List<AzureIdentityRole>();
                    }
                }
                return _roles;
            }
        }

        [NonSerializedTableStore]
        internal Func<IEnumerable<AzureIdentityClaim>> LazyClaimsEvaluator { get; set; }

        private List<AzureIdentityClaim> _claims;
        [NonSerializedTableStore]
        public ICollection<AzureIdentityClaim> Claims
        {
            get
            {
                if (_claims == null)
                {
                    if (LazyClaimsEvaluator != null)
                    {
                        _claims = new List<AzureIdentityClaim>(LazyClaimsEvaluator());
                    }
                    else
                    {
                        _claims = new List<AzureIdentityClaim>();
                    }
                }
                return _claims;
            }
        }

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<AzureIdentity> manager, string authenticationType)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, authenticationType);
            
            // Add custom user claims here
            //Put the user Id in here JMR
            userIdentity.AddClaim(new Claim("UserId", this.Id));

            return userIdentity;
        }


        [NonSerializedTableStore]
        internal Func<IEnumerable<AzureIdentityLogin>> LazyLoginEvaluator { get; set; }

        private List<AzureIdentityLogin> _logins;
        [NonSerializedTableStore]
        public ICollection<AzureIdentityLogin> Logins
        {
            get
            {
                if (_logins == null)
                {
                    if (LazyLoginEvaluator != null)
                    {
                        _logins = new List<AzureIdentityLogin>(LazyLoginEvaluator());
                    }
                    else
                    {
                        _logins = new List<AzureIdentityLogin>();
                    }
                }
                return _logins;
            }
        }
        private string AsRowKey(Guid id)
        {
            return id.ToString("N");
        }
        public AzureIdentity()
        {
            this.Id = AsRowKey(Guid.NewGuid());

            SetPartitionAndRowKey();
        }

        public AzureIdentity(Guid userId)
        {
            this.Id = AsRowKey(userId);

            SetPartitionAndRowKey();
        }

        public AzureIdentity(Guid userId, string userName)
        {
            this.Id = AsRowKey(Guid.NewGuid());
            this.UserName = userName;
            SetPartitionAndRowKey();
        }

        public override IDictionary<string, EntityProperty> WriteEntity(Microsoft.WindowsAzure.Storage.OperationContext operationContext)
        {
            var entityProperties = base.WriteEntity(operationContext);
            var objectProperties = GetType().GetProperties();

            foreach (var property in from property in objectProperties
                                     let nonSerializedAttributes = property.GetCustomAttributes(typeof(NonSerializedTableStoreAttribute), false)
                                     where nonSerializedAttributes.Length > 0
                                     select property)
            {
                entityProperties.Remove(property.Name);
            }

            return entityProperties;
        }
    }
}
