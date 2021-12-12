# Group2role sync

This python example demonstrates the usage of IDCS REST API.
The main objective is to demonstrate how the SCIM GRANT API for application roles 

## Usecase

IDCS defines two types of applications, the applications you may create by you selves either from the application 
catalog or the prebuilt templates or a set of applications under “Oracle Cloud Services” menu.

The later are a set of applications that you cannot create or delete, they are created by Oracle OCI, representing 
services like OAC, Fusion ERP or EPM, among others.

The “Oracle Cloud Services” type of application has a tab “application roles” where IDCS users or IDCS 
groups may be assigned to the application role. The semantics of this assignment is dependent on the actual 
service the “Oracle Cloud Service” object represents.

![IDCS Groups](/images/groups)

![IDCS Group members](/images/group_members.JPG)

![IDCS applications](/images/applications.JPG)

![IDCS applications](/images/appliication_roles.JPG)

The sample code her, creates a relationship between an IDCS group and an application role for the cases where o
nly IDCS uses can be assigned to an application role and not groups.

## Program execution

The program is run as follows:
python3 group2role –configfile <config.json> --idcsname < IDCSshortname in the configfile>\
The config file has the following format:\

		
{
	"IDCSinstances": [{
			"name": "IDCSshortname",
			"clientid": "<xxx>",
			"clientsecret": "<xxx>",
			"idcsapiuri": "https://idcs-<tenant>.identity.oraclecloud.com",
			"syncgroups": [{
					"groupname": "<name of IDCS group>",
					"oracleservicename": "<name of service>",
					"rolename": "<name of role>"
				},
				{
					"groupname": "<name of IDCS group>",
					"oracleservicename": "<name of service>",
					"rolename": "<name of role>"
				}
			]
		}
	]
}

There is a json array that describes which groups should be synced to which application role for 
which application under “Oracle Cloud Services” 

## REST APIs used

Get a user token (POST, /oauth2/v1/token)\
https://docs.oracle.com/en/cloud/paas/identity-cloud/rest-api/op-oauth2-v1-token-post.html \\
Search Groups with filter (GET, /admin/v1/Groups)\
https://docs.oracle.com/en/cloud/paas/identity-cloud/rest-api/op-admin-v1-groups-get.html\\
Search App Roles with filter (GET, /admin/v1/AppRoles)\
https://docs.oracle.com/en/cloud/paas/identity-cloud/rest-api/op-admin-v1-approles-get.html\\
Search Grants with filter (GET, /admin/v1/Grants)\
https://docs.oracle.com/en/cloud/paas/identity-cloud/rest-api/op-admin-v1-grants-get.html\\
Add a Grantee to an AppRole (POST, /admin/v1/Grants)\
https://docs.oracle.com/en/cloud/paas/identity-cloud/rest-api/op-admin-v1-grants-post.html\\
Remove a Grantee from an AppRole (DELETE, /admin/v1/Grants)\
https://docs.oracle.com/en/cloud/paas/identity-cloud/rest-api/op-admin-v1-grants-id-delete.html\\

## Quick program flow

The program is quite simple:
- Generate token for the IDCS stripe or Identity Domain
- Iterate over the syncgroups from the configfile
-- Fetch all group members of the given group
-- Fetch all members of the given application role
-- Grant access to users defined in the group that is missing
-- Revoke users in the application role, not defined in the corresponding group

(c) Inge Os 01.12.2021
	 
