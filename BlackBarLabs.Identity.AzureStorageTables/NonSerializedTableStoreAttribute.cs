using System;

namespace BlackBarLabs.Identity.AzureStorageTables
{
    [AttributeUsage(AttributeTargets.Property)]
    public class NonSerializedTableStoreAttribute : Attribute
    {

    }
    
}
