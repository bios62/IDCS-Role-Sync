import sys
import requests 
import argparse
import json
import urllib.parse
from urllib.parse import urlencode, quote_plus
import base64
import os.path
#
# Python 3
#
# Program that demostrates sync between IDCS group and IDCS application roles
# The objective is to define a IDCS group and assign users to the group
# The users are then added or removed from an Oracle Cloud Service role based on group membership in the group
#
# Usage: rolecync --configfile filename --idcsname IDCSshortname
#
#  filename= name of configfile, including path
#  IDCSshortname, referenced in configfile to pick up correct clientid/secret and URL
#
# (c) Inge Os 5/10-2020
#
# Config file parameters
#
# Common
# 
# Example config file
#{
#	"IDCSinstances": [{
#			"name": "epm>",
#			"clientid": "fe40d31e18f2492aa8324666cae08a4c",
#           "clentsecret": "c0048e8a-4875-4584-85f7-dbbf4372bcfa",
#			"idcsapiuri": "https://idcs-2a47d859a6dd413a8c78b87ba129f293.identity.oraclecloud.com/",
#			"syncgroups": [{
#					"groupname": "epm_power_user",
#					"oracleservicename": "Planning_epm2-test",
#					"rolename": "Power User"
#				},
#				{
#					"groupname": "EPM_service_administrator",
#					"oracleservicename": "Planning_epm2-test",
#					"rolename": "Service Administrator"
#				}
#			]
#		},
#		{
#			"name": "<IDCSshortname>",
#			"clientid": "<xxx>",
#			"clentsecret": "<xxx>",
#			"idcsapiuri": "<https://idcs-<tenant>.identity.oraclecloud.com>",
#			"syncgroups": [{
#					"groupname": "<name of IDCS group>",
#					"oracleservicename": "<name of service>",
#					"rolename": "<name of role>"
#				},
#				{
#					"groupname": "<name of IDCS group>",
#					"oracleservicename": "<name of service>",
#					"rolename": "<name of role>"
#				}
#			]
#		}
#	]
#}
# Status
#   Initial coding started
#   Prettyprint  not verified
#   loadConfig   Verified
#   printHTTPerror  not verified
#   getUserList   needs to be rewritten
#   getToken     Verified
#   main        under development
#   
# Globals 
#
version="1.0 Demo 12/12-2021  (c) Inge Os"
debug=True
#
# For POST request, prettyprint the request
#
def pretty_print_POST(req):
	"""
	At this point it is completely built and ready
	to be fired; it is "prepared".

	However pay attention at the formatting used in 
	this function because it is programmed to be pretty 
	printed and may differ from the actual request.
	"""
	print('{}\n{}\r\n{}\r\n\r\n{}'.format(
		'-----------START-----------',
		req.method + ' ' + req.url,
		'\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
	req.body,
	))
#
# Loads configfile
#
# Json file with the following mandatory items
# "idcsAPIUri","clientid","sharedsecret"
#  promt for values if not supplied
#
#  Needs to be rewritten
def loadConfig(configFile):
	configItem={"idcsapiuri","clientid","clientsecret"}
	#
	# Load config data from config file
	#
	with open(configFile, 'r') as file: 
		configData = json.loads(file.read().replace('\n', ''))
	return(configData)
#
# Error routine that prints the REST call
#
def printHTTPerror(errorMSG,statusCode,uri,headers,payload,method):
	print(errorMSG+str(statusCode))
	print("IDCS tenant: "+uri)
	if(debug) :
		dbgreq=requests.Request(method,uri,headers=headers)
		prepared=dbgreq.prepare()
		print(" HTTP Request")
		pretty_print_POST(prepared)
#
# User curlapi  to authenticate and retrieve Bearer token
# Returns False if HTTPcode 200 or HTTPcode 201 is not received
# HTTPcode 200 or HTTPcode gives a valid token
# Return the Bearer token if HTTPcode <=201
#
# input:
#	tenant, dict with the following members: tenant['clientid'], tenant['clientsecret'], tenant['idcsapiuri']
def getToken(tenant):

	auth64=base64.b64encode((tenant['clientid']+":"+tenant['clientsecret']).encode('ascii')).decode('utf-8')
	headers = {"content-type": "application/x-www-form-urlencoded","Authorization":"Basic "+auth64}

	endpoint=tenant['idcsapiuri']+"/oauth2/v1/token"
	data="grant_type=client_credentials&scope=urn:opc:idm:__myscopes__"
	r = requests.post(endpoint, headers=headers,data=data)

	if r.status_code > 201:
		print("Authorization request failed with status: "+str(r.status_code))
		print("IDCS tenant: "+tenant['idcsapiuri'])
		if(debug) :
			dbgreq=requests.Request('POST',endpoint,headers=headers,data=data)
			prepared=dbgreq.prepare()
			pretty_print_POST(prepared)
		return(False)
	else:
		return(json.loads(r.text)['access_token'])
#
#  Process one IDCS instance
#  There is an array of group to role mappings, each processed as follows
#  Feth the IDCS group
#  Fetch all users in the group
#  Fetch userNames from the userid
#  Fetch application
#  Fetch role of application
#  Fetch all grants
#  Loop through all userid from the IDCS groupo, collect all missing grants
#  Loop through all role grants, generate all grants to be rovekd by matching against list of user from IDCS group
#
def processIdcsSync(idcsInstance):
	#
	# Generate API token
	#
	tenant=dict()
	tenant['clientid']=idcsInstance['clientid']
	tenant['clientsecret']=idcsInstance['clientsecret']
	tenant['idcsapiuri']=idcsInstance['idcsapiuri']
	tenant['token']=getToken(tenant)
	if tenant['token'] == False:
		print("token creation for: "+idcsInstance['name']+" failed")
		return(False)
	#
	# Loop throug all group to role mappings
	#
	for i in range(0,len(idcsInstance['syncgroups'])):
		print()
		print("Processing application: "+idcsInstance['syncgroups'][i]['oracleservicename'])
		print()
		groupMembers=getUserList(tenant,idcsInstance['syncgroups'][i])
		roleGrants=getRoleGrants(tenant,idcsInstance['syncgroups'][i])
		if not groupMembers is False and not roleGrants is False:
			addUsersToRole(groupMembers,roleGrants,idcsInstance['syncgroups'][i],tenant)
			print()
			revokeUsersFromRole(groupMembers,roleGrants,idcsInstance['syncgroups'][i],tenant)
		else:
			if groupMembers is False:
				print("Group: "+idcsInstance['syncgroups'][i]['groupname']+" do not exists in idcs instance: "+idcsInstance['name'])
			if roleGrants is False:
				print("Application role: "+idcsInstance['syncgroups'][i]['rolename']+" do not exists or application: "+idcsInstance['syncgroups'][i]['oracleservicename']+" dont exists")
#
#
# getUserList
#
# fetches all user ID's from the list of users who are members of a given group, in syncGroup
#
# return array of groupMemers.
#	Each group member is a dict as follows
#				groupMember["id"]  Id of users
#				groupMember["name"]   Name of user
# Status: complete
#
def getUserList(tenant,syncGroup):
	#
	# Construct apiRUL fro group retrieval
	#
	endpoint=tenant['idcsapiuri']+"/admin/v1/Groups?filter=displayName%20eq%20%22"+syncGroup['groupname']+"%22&attributes=members"
	#
	# Do the get request for fetching all users matching the criteria
	#
	headers = {"content-type": "application/scim+json","Authorization":"Bearer "+tenant['token']}
	r = requests.get(endpoint, headers=headers)
	if r.status_code > 201:
		print("Authorization request failed with status: "+str(r.status_code))
		print("IDCS tenant: "+endpoint)
		if(debug) :
			dbgreq=requests.Request('GET',endpoint,headers=headers)
			prepared=dbgreq.prepare()
			pretty_print_POST(prepared)
		return(False)
	#
	# The request should return exactly one group#
	#
	jgroups=json.loads(r.text)
	if len(['Resources']) != 1 :
		print("The group lookup of "+syncGroup+" returned :"+len(['Resources'])+" records")
		return(False)
	#
	groupMembers=[]
	
	if jgroups["totalResults"] > 0 and "members" in jgroups['Resources'][0]:
		for i in range(0,len(jgroups['Resources'][0]['members'])):
			if(jgroups['Resources'][0]['members'][i]['type'] == "User"):
				groupMember={}
				groupMember["id"]=jgroups['Resources'][0]['members'][i]['value']
				groupMember["name"]=jgroups['Resources'][0]['members'][i]['name']
				groupMembers.append(groupMember)
		return(groupMembers)
	else:
		return(False)
#
#
#  getRoleGrants
#
#  fetches all user ID's from the list of grants to a given role
#  Returns an array of Grants, where the userid is a part of the record
#
#	Return a dict of following format:
#				['appRoleId']=Application role ID
#				['appId']=Application ID
#				['grants']=array of grants as dict in the follwoing forat
#					['grantid']=
#					['userid']=
#
#
def getRoleGrants(tenant,syncGroup):
	#
	# Construct apiRUL for app retrieval
	# The appid is fetched with the appName in the filter
	#
	appName=syncGroup['oracleservicename']
	roleName=syncGroup['rolename']
	api=tenant['idcsapiuri']+"/admin/v1/AppRoles"
	endpoint=api+"?filter=app.display%20eq%20%22"+appName+"%22%20and%20displayName%20eq%20%22"+roleName+"%22"
	#
	# Do the get request for fetching all users matching the criteria
	#
	headers = {"content-type": "application/scim+json","Authorization":"Bearer "+tenant['token']}
	r = requests.get(endpoint, headers=headers)
	if r.status_code > 201:
		print("Authorization request failed with status: "+str(r.status_code))
		print("IDCS tenant: "+endpoint)
		if(debug) :
			dbgreq=requests.Request('GET',endpoint,headers=headers)
			prepared=dbgreq.prepare()
			pretty_print_POST(prepared)
		return(False)
	oracleApp=json.loads(r.text)
	#
	# The search should return exactly one resource
	#
	numRec=len(oracleApp['Resources'])
	if( numRec != 1):
		print("Incorrect number of records ("+str(numRec)+") (Exactly one required) found for Oracle Cloud Service: "+appName)
		print(r.text)
		return(False)
	#
	# Fetch all grants for applicable appid
	##
	# Construct apiRUL for approle retrieval
	#
	api=tenant['idcsapiuri']+"/admin/v1/Grants"
	endpoint=api+"?filter=entitlement[attributeName%20eq%20%22appRoles%22%20and%20attributeValue%20eq%20%22"
	endpoint=endpoint+oracleApp['Resources'][0]['id']+"%22]"
	#
	# Do the get request for fetching all users matching the criteria
	#
	headers = {"content-type": "application/scim+json","Authorization":"Bearer "+tenant['token']}
	r = requests.get(endpoint, headers=headers)
	if r.status_code > 201:
		print("Authorization request failed with status: "+str(r.status_code))
		print("IDCS tenant: "+endpoint)
		if(debug) :
			dbgreq=requests.Request('GET',endpoint,headers=headers)
			prepared=dbgreq.prepare()
			pretty_print_POST(prepared)
		return(False)
	#
	# Iterate over grants and fetch userid
	#

	jGrants=(json.loads(r.text)) ['Resources']
	allGrants=[]

	for grant in jGrants:
		nextGrant={}
		if grant['grantee']['type'] == "User":
			nextGrant['userid']=grant['grantee']['value']  # id of user
			nextGrant['grantid']=grant['id']    # value of grant, used for revoke
			allGrants.append(nextGrant)
	grantObject={}
	grantObject['appRoleId']=oracleApp['Resources'][0]['id']
	grantObject['appId']=oracleApp['Resources'][0]['app']['value']
	grantObject['grants']=allGrants
	return(grantObject)

#
#  addUsersToRole
#
# Iterate over all users in userList and add
# missing users to the application role
#
def addUsersToRole( groupMembers,roleGrantObjects,syncGroup,tenant):
	#
	# Iterate over all userIDs
	#
	print("Processing group: "+syncGroup['groupname'])
	if groupMembers is not False:
		for i in range(0,len(groupMembers)):
			granted=isGranted(groupMembers[i]['id'],roleGrantObjects['grants'])
			if granted is False:
				print("User: "+ groupMembers[i]['name']+" userid: "+groupMembers[i]['id']+ "  will be granted to:"+syncGroup['oracleservicename']+" Role:"+syncGroup['rolename'])
				#print("Appid: "+roleGrantObjects['appId']+" RoleId: "+roleGrantObjects['appRoleId'])
				#
				#  Grant apporole to user
				#
				endpoint=tenant['idcsapiuri']+"admin/v1/Grants"
				payload='{"grantee":{"type":"User","value":"'+ groupMembers[i]['id']+'"},"app":{"value":"'+roleGrantObjects['appId']
				payload=payload+'"},"entitlement":{"attributeName":"appRoles","attributeValue":"'+roleGrantObjects['appRoleId']+'"}'
				payload=payload+',"grantMechanism":"ADMINISTRATOR_TO_USER","schemas":["urn:ietf:params:scim:schemas:oracle:idcs:Grant"]}'
				#
				# Do the get request for fetching all users matching the criteria
				#
				headers = {"content-type": "application/scim+json","Authorization":"Bearer "+tenant['token']}
				r = requests.post(endpoint, headers=headers, data=payload)
				if r.status_code > 201:
					print("Grant request request failed with status: "+str(r.status_code))
					print("IDCS tenant: "+endpoint)
					if(debug) :
						dbgreq=requests.Request('POST',endpoint,headers=headers,data=payload)
						prepared=dbgreq.prepare()
						pretty_print_POST(prepared)
					return(False)
				else:
					print("User: "+groupMembers[i]['name']+" Granted Successfully")
			else:
				print("user: "+ groupMembers[i]['name']+ " userid: "+groupMembers[i]['id']+"  is mapped to: "+syncGroup['rolename']+" grant id: "+roleGrantObjects['grants'][granted]['grantid'])
#
#  lookup if a userid exists in grants oject
#
def isGranted(userId,grants):
	for i in range(0,len(grants)):
		if(userId == grants[i]['userid']):
			return(i)
	return(False)
#
# revokeUsersFromRole
#
# Iterate over all users in userList and add
# missing users to the application role
#
def revokeUsersFromRole(groupMembers,roleGrants,syncGroup,tenant):
	#
	# Iterate over all roles
	#
	print("Prosessing application role: "+syncGroup['rolename'])
	#
	# Iterate over all grans and lookup if the grantee is a member of the group
	#
	revokedUsers=0
	for i in range(0,len(roleGrants['grants'])):
		found=False
		#
		#  loop though all members to find the grantee
		if groupMembers != False:
			for j in range(0,len(groupMembers)):
				if roleGrants['grants'][i]['userid'] == groupMembers[j]['id']:
					found=True
					break
		#
		# If the grantee is not a member of the group revoke the application access
		#
		if(not found):
			endpoint=api=tenant['idcsapiuri']+"admin/v1/Grants/"+roleGrants['grants'][i]['grantid']
			#
			# Do the get request for fetching all users matching the criteria
			#
			print("Revoking userid: "+roleGrants['grants'][i]['userid'])
			headers = {"content-type": "application/scim+json","Authorization":"Bearer "+tenant['token']}
			r = requests.delete(endpoint, headers=headers)
			if r.status_code != 204:
				#print("Revoke of grant for: "+roleMemberList['grants'][i]['userid']+" from role: "+roleMemberList+"" failed with status: "+str(r.status_code))
				print("IDCS tenant: "+endpoint)
				if(debug) :
					dbgreq=requests.Request('DELETE',endpoint,headers=headers)
					prepared=dbgreq.prepare()
					pretty_print_POST(prepared)
				return(False)
			revokedUsers+=1
			print("Revoked successfully")
	if revokedUsers == 0:
		print("No group assigned users found in role")
	else:
		print("Revoked "+str(revokedUsers))


#
#  Main 
#
def main(argv):
	#
	# Parse args
	#
	argsParser=argparse.ArgumentParser(description='Rolesync Comandline')
	argsParser.add_argument("--configfile",default="rolesync.json",type=str,help="Filename of JSON config file")
	argsParser.add_argument("--idcsname",default=None,type=str,help="Short name of IDCS stripe referenced in configfile")
	args=argsParser.parse_args()
	#
	# Verify args
	#
	usage="--configfile filename --idcsname IDCSshortname"
	print()
	print("IDCS REST API demo program for IDCS group to IDCS application role sync")
	print(version)
	if not os.path.isfile(args.configfile):
		print("configuration file does not exxists")
		print(usage)
		exit(1)
	# 
	# Load config
	# exist with status 1 if mandatory items are missing
	#
	idcsConfig=loadConfig(args.configfile)
	#
	# Verify if IDCSinstances is defined
	#
	if not 'IDCSinstances' in idcsConfig:
		print("Member IDCSinstances not defined correctly in json config file")
		exit(1)
	#
	# Process each set IDCS instances
	#
	if(args.idcsname == None):
		#
		# Iterate over all
		#
		for i in range(0,len(idcsConfig['IDCSinstances'])):
			processIdcsSync(idcsConfig['IDCSinstances'][i])
	else:
		#
		# Lookup spesific
		#
		idcsStripe=None
		for i in range(0,len(idcsConfig['IDCSinstances'])):
			if(idcsConfig['IDCSinstances'][i]['name'] == args.idcsname):
				idcsStripe=i	
				break
		if idcsStripe is None:
			print("IDCSinsatce does not have entry with name: "+args.idcsname)
			exit(1)
		processIdcsSync(idcsConfig['IDCSinstances'][idcsStripe])


if __name__ == '__main__':
	main(sys.argv)