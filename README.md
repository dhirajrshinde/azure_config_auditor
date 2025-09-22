# Azure Auditor
This is a Python-based tool for auditing key Azure resources across a subscription. It checks for common misconfigurations and security risks in:

- Network Security Groups (NSGs)
- Storage Accounts (public blob access)
- Azure Active Directory Users (MFA status)

## Features

- Identifies NSG rules allowing unrestricted inbound traffic (0.0.0.0/0)
- Checks if storage accounts have blob public access enabled
- Verifies if MFA is enabled for Azure AD users
- Generates a detailed JSON report with all findings

## Prerequisites

- Python 3.8 or later
- Azure CLI (logged in)
- Necessary Azure SDK packages installed
