```html
# guestb2b-remediate
Restrict guest user access to applications

Demand for external collaboration and sharing of documents with 3rd parties is constantly growing. Global initiatives are in the process of selecting tactical solutions due to the lack of strategic, enterprise-wide, easy-to-use external collaboration capabilities.
One of the key priority controls is to increase security for our Azure AD environments, and apply access restrictions to applications in the Azure AD tenants, that are intended to be accessed only by company employees and contractors.
Azure service principals that correspond to applications that do not require guest user logins should be configured to prevent guest users from logging in.  

To remediate guest access apply following changes at application Service Principal level:

- Set User assignment required option to Yes
- Set Visible to users option to No
- Assign dedicated dynamic group to Service Principal, which holds all user of Member type

Dynamic Groups usage limitation:

- An undocumented limitation on the number of AppRoleAssignments that may be associated with a group (Microsoft confirmed 1500 assignments)
- A bug that prevents errors from being reported when this limitation is reached.
- A bug that only allows for a maximum of 999 AppRoleAssignments from being read/listed

Prerequisites
- AzureAD or AzureADPreview PowerShell module available/installed.
- PowerShell session successfully connected to target Azure tenant with Connect-AzureAD cmdlet. 
- List of target Service Principals identifiers available, mapped to target dynamic group (no more than 950 objects per file):

Please refer to implementation.pdf for full details.
```
