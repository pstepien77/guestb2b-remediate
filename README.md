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

-	An undocumented limitation on the number of AppRoleAssignments that may be associated with a group (Microsoft confirmed 1500 assignments)
-	A bug that prevents errors from being reported when this limitation is reached.
-	A bug that only allows for a maximum of 999 AppRoleAssignments from being read/listed

Prerequisites
-	AzureAD or AzureADPreview PowerShell module available/installed.
-	PowerShell session successfully connected to target Azure tenant with Connect-AzureAD cmdlet. 
-	List of target Service Principals identifiers available, mapped to target dynamic group (no more than 950 objects per file):

Input file name with Service Principals	Target dynamic group

R1.txt	--> ALL-MEMBER-USERS-R1
R2.txt	--> ALL-MEMBER-USERS-R2
...
Rn.txt	--> ALL-MEMBER-USERS-Rn

Input File example (with the header)

ObjectId
650c92f1-9477-493a-bb92-5e4b3c60c398
df32279e-e297-4831-b22e-09ce222e1606
225971fb-75cb-427e-a9d1-1955e647ba7b
e1d73369-bc15-41e1-aa5e-3a5376927da2
5fb098d3-8fcf-4ae1-bd40-89ff2bfb1912
01cc0374-d82a-44f3-870e-ad2bcad8a87e


