import json
import re
import requests
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient


def check_users():
    credential = DefaultAzureCredential()
    token = credential.get_token("https://graph.microsoft.com/.default").token
    headers = {"Authorization": f"Bearer {token}"}
    users = []
    url = "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName"
    while url:
        resp = requests.get(url, headers=headers)
        data = resp.json()
        users.extend(data.get("value", []))
        url = data.get("@odata.nextLink")

    findings = []
    for user in users:
        mfa_url = f"https://graph.microsoft.com/v1.0/users/{user['id']}/authentication/methods"
        mfa_resp = requests.get(mfa_url, headers=headers)
        mfa_methods = mfa_resp.json().get("value", [])
        has_mfa = any(
            m["@odata.type"] in [
                "#microsoft.graph.phoneAuthenticationMethod",
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
                "#microsoft.graph.fido2AuthenticationMethod"
            ]
            for m in mfa_methods
        )
        if not has_mfa:
            findings.append({
                "resource": user["userPrincipalName"],
                "type": "User",
                "issue": "MFA not enabled",
                "severity": "High"
            })
        else:
            findings.append({
                "resource": user["userPrincipalName"],
                "type": "User",
                "issue": "No issue found",
                "severity": "Low"
            })
    return findings


def check_nsg_rules(subscription_id):
    credential = DefaultAzureCredential()
    network_client = NetworkManagementClient(credential, subscription_id)
    findings = []
    for nsg in network_client.network_security_groups.list_all():
        for rule in nsg.security_rules:
            if rule.direction == "Inbound" and rule.access == "Allow":
                if rule.source_address_prefix in ["0.0.0.0/0", "*"]:
                    findings.append({
                        "resource": nsg.name,
                        "type": "NSG",
                        "issue": f"Rule '{rule.name}' allows inbound from 0.0.0.0/0",
                        "severity": "High"
                    })
            else:
                findings.append({
                        "resource": nsg.name,
                        "type": "NSG",
                        "issue": "No issue found",
                        "severity": "Low"
                    })
    return findings


def get_resource_group_from_id(resource_id):
    match = re.search(r"/resourceGroups/([^/]+)/", resource_id, re.IGNORECASE)
    return match.group(1) if match else None


def check_storage_accounts(subscription_id):
    credential = DefaultAzureCredential()
    storage_client = StorageManagementClient(credential, subscription_id)
    findings = []
    for account in storage_client.storage_accounts.list():
        resource_group = get_resource_group_from_id(account.id)
        props = storage_client.storage_accounts.get_properties(resource_group, account.name)
        if props.allow_blob_public_access:
            findings.append({
                "resource": account.name,
                "type": "StorageAccount",
                "issue": "Blob public access is enabled",
                "severity": "High"
            })
        else:
            findings.append({
                "resource": account.name,
                "type": "StorageAccount",
                "issue": "No issue found",
                "severity": "Low"
            })
    return findings


def generate_report(findings, filename="audit_report.json"):
    with open(filename, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"Report generated: {filename}")


def main():
    subscription_id = "d6b8867d-9cd0-40fa-ab99-55fc3667241b"
    findings = []
    findings.extend(check_nsg_rules(subscription_id))
    findings.extend(check_users())
    findings.extend(check_storage_accounts(subscription_id))
    generate_report(findings)


if __name__ == "__main__":
    main()
