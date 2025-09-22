import re
import requests
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient

def print_nsg_metadata(subscription_id):
    credential = DefaultAzureCredential()
    network_client = NetworkManagementClient(credential, subscription_id)

    print("PRINTING NSG DATA\n")
    for nsg in network_client.network_security_groups.list_all():
        print(f"NSG Name: {nsg.name}")
        print(f"Location: {nsg.location}")
        print(f"Resource Group: {nsg.id.split('/')[4]}")
        print(f"Tags: {nsg.tags}")
        print(f"Security Rules:")
        for rule in nsg.security_rules:
            print(f"  - Name: {rule.name}, Direction: {rule.direction}, Access: {rule.access}, Source: {rule.source_address_prefix}")
        print("--------------------------------------------------")
    print("\n\n")

def print_user_metadata():
    credential = DefaultAzureCredential()
    token = credential.get_token("https://graph.microsoft.com/.default").token
    headers = {
        "Authorization": f"Bearer {token}"
    }
    url = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,jobTitle,department"
    users = []
    print("PRINTING USERS\n")
    while url:
        resp = requests.get(url, headers=headers)
        data = resp.json()
        users.extend(data.get("value", []))
        url = data.get("@odata.nextLink")

    for user in users:
        print(f"User Principal Name: {user.get('userPrincipalName')}")
        print(f"Display Name: {user.get('displayName')}")
        print(f"Job Title: {user.get('jobTitle')}")
        print(f"Department: {user.get('department')}")
        print("--------------------------------------------------")
    print("\n\n")

def get_resource_group_from_id(resource_id):
    match = re.search(r"/resourceGroups/([^/]+)/", resource_id, re.IGNORECASE)
    return match.group(1) if match else None

def print_storage_metadata(subscription_id):
    credential = DefaultAzureCredential()
    storage_client = StorageManagementClient(credential, subscription_id)

    print("PRINTING STORAGE ACCOUNTS\n")
    for account in storage_client.storage_accounts.list():
        resource_group = get_resource_group_from_id(account.id)
        props = storage_client.storage_accounts.get_properties(resource_group, account.name)

        print(f"Storage Account Name: {account.name}")
        print(f"Location: {account.location}")
        print(f"Resource Group: {resource_group}")
        print(f"Allow Blob Public Access: {props.allow_blob_public_access}")
        print(f"Sku: {account.sku.name if account.sku else 'N/A'}")
        print(f"Tags: {account.tags}")
        print("--------------------------------------------------")
    print("\n\n")

def main():
    subscription_id = "d6b8867d-9cd0-40fa-ab99-55fc3667241b"

    print_nsg_metadata(subscription_id)
    print_user_metadata()
    print_storage_metadata(subscription_id)

if __name__ == "__main__":
    main()
