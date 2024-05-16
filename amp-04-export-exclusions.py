import json
import os
import requests

from dotenv import load_dotenv

# Load .env file variables
load_dotenv()
CLIENT_ID = os.getenv('CLIENT_ID')
API_KEY = os.getenv('API_KEY')

if not CLIENT_ID or not API_KEY:
	raise "Need a CLIENT_ID and/or API_KEY variables added to .env file"

CLOUD = os.getenv("CLOUD")
if CLOUD == "NAM":
	base_securex_url = "https://visibility.amp.cisco.com"
	base_secure_endpoint_url = "https://api.amp.cisco.com/v3"
elif CLOUD == "EU":
	base_securex_url = "https://visibility.eu.amp.cisco.com"
	base_secure_endpoint_url = "https://api.eu.amp.cisco.com/v3"
elif CLOUD == "APJC":
	base_securex_url = "https://visibility.apjc.amp.cisco.com"
	base_secure_endpoint_url = "https://api.apjc.amp.cisco.com/v3"
else:
	raise "Need a CLOUD variable (NAM|EU|APJC) added to .env file"

def get_se_access_token():
    """
    Authenticate with SecureX to get a token.  Then authenticate with Secure Endpoints.
    :return Secure Endpoints access token
    """

    auth = (CLIENT_ID, API_KEY)
    securex_url = f"{base_securex_url}/iroh/oauth2/token"
    data = {"grant_type": "client_credentials"}
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }

    # Authenticate with SecureX and get an access_token
    sx_response = requests.post(securex_url, headers=headers, data=data, auth=auth)
    if sx_response.status_code == 400:
        exit("Please check your .env file for proper credentials and try again.")
    sx_access_token = (sx_response.json().get("access_token"))

    # Get Secure Endpoints access_token
    secure_endpoint_url = f"{base_secure_endpoint_url}/access_tokens"
    headers = {
        'Authorization': f'Bearer {sx_access_token}'
    }
    se_response = requests.post(secure_endpoint_url, headers=headers)
    se_access_token = se_response.json().get("access_token")

    return se_access_token

def get_organization_id(se_access_token):
    """
    Authenticate with the Secure Endpoint access token and choose an organization.
    The chosen organization ID will be used to pull exclusion information.
    :param se_access_token Secure Endpoints access token
    :return Organization ID of the chosen organization
    """
    choice = ''
    org_url = f"{base_secure_endpoint_url}/organizations"
    data={"size": 100}
    headers = {'Authorization': f'Bearer {se_access_token}'}
    org_response = requests.get(org_url, headers=headers, data=data)

    print("Which organization would you like to list exclusions from?")
    for idx, org in enumerate(org_response.json().get('data')):
        print(f"[{idx + 1}] - {org['name']}")

    try:
        choice = int(input("Input a number listed above: ")) - 1
    except ValueError as e:
        print("A number from the list provided is required.  Please try again")
        org_id = get_organization_id(se_access_token)
        return org_id

    if choice >= 0 and choice < len(org_response.json().get('data')):
        org_id = org_response.json().get('data')[choice]['organizationIdentifier']
        return org_id

    else:
        print("A number from the list provided is required.  Please try again")
        org_id = get_organization_id(se_access_token)
        return org_id

def get_exclusion_sets(se_access_token, org_id, start=0, exclusion_sets=[]):
    """
    Pull all the avaiable exclusion sets from an organization and return them in a list
    :param se_access_token Secure Endpoints access token
    :param org_id Organization ID of the chosen organization
    :param start What item to start on for the exclusion sets API call, used for pagination
    :param exclusion_sets List of previously pulled exclusion sets, used for pagination
    :return exclusion_sets List of all exlusion sets for an org
    """
    exclusion_sets_url = f"{base_secure_endpoint_url}/organizations/{org_id}/exclusion_sets"
    data = {
        "size": 100,
        "start": start
    }
    headers = {'Authorization': f'Bearer {se_access_token}'}
    exclusion_sets_response = requests.get(exclusion_sets_url, headers=headers, data=data)
    for exclusion_set in exclusion_sets_response.json().get('data'):
        exclusion_sets.append(exclusion_set)
    current_index = start + exclusion_sets_response.json().get('meta').get('size')
    if exclusion_sets_response.json().get('meta').get('total') > current_index:
        get_exclusion_sets(se_access_token, org_id, start=current_index, exclusion_sets=exclusion_sets)    

    return exclusion_sets

def select_exclusion_set(exclusion_sets, se_access_token, org_id):
    """
    Show all available exclusion sets and select one for further processing.
    :param exclusion_sets List of exclusion sets
    :param se_access_token Secure Endpoints access token
    :param org_id Organization ID of the chosen organization
    :return exclusion_set A single exclusion set selected by the user (unless they chose to process all sets)
    """
    choice = ''
    if len(exclusion_sets) == 0:
        exit("There are no exclusion sets for this organization.")
    print("Which exclusion set would you like to list exclusions from?")
    for idx, exclusion_set in enumerate(exclusion_sets):
        print(f"[{idx + 1}] - {exclusion_set['properties']['name']}")
    print(f"[{idx + 2}] - All exlcusion lists. NOTE: May be very time intensive depending on the volume.")
    try:
        choice = int(input("Input a number listed above: ")) - 1
    except ValueError as e:
        print("A number from the list provided is required.  Please try again.")
        exclusion_set = select_exclusion_set(exclusion_sets, se_access_token, org_id)
        return exclusion_set
    if choice >= 0 and choice < len(exclusion_sets):
        return exclusion_sets[choice]
    elif choice == len(exclusion_sets):
        process_all(exclusion_sets, se_access_token, org_id)
    else:
        print("A number from the list provided is required.  Please try again.")
        exclusion_set = select_exclusion_set(exclusion_sets, se_access_token, org_id)
        return exclusion_set

def get_exclusion_set_data(se_access_token, org_id, exclusion_set_info, start=0, exclusions=[]):
    """
    Pull exclusions from an exclusion set
    :param se_access_token Secure Endpoints access token
    :param org_id Organization ID of the chosen organization
    :param exclusion_set_info Name, guid and operating system of an exclusion set
    :param start What item to start on for the exclusion sets API call, used for pagination
    :param exclusions List of previously pulled exclusions, used for pagination
    :return exclusion_set_data All data for an exclusion set, including all exclusions 
    """
    url = f"{base_secure_endpoint_url}/organizations/{org_id}/exclusion_sets/{exclusion_set_info['guid']}/exclusions"
    data = {
        "size": 100,
        "start": start
    }
    headers = {'Authorization': f'Bearer {se_access_token}'}

    response = requests.get(url, headers=headers, data=data)
    for exclusion in response.json().get('data'):
        exclusions.append(exclusion)
    current_index = start + response.json().get('meta').get('size')
    if response.json().get('meta').get('total') > current_index:
        get_exclusion_set_data(se_access_token, org_id, exclusion_set_info, start=current_index, exclusions=exclusions)
    return response.json().get('data')

def export_to_json(exclusion_set_data, exclusion_set_info):
    """
    Export an exclusion set to a json file in the local directory
    :param exclusion_set_data All data for an exclusion set, including all exclusions
    :param exclusion_set_info Dictionary with name, guid and operatingSystem of an exclusion set
    """
    with open(f'{exclusion_set_info["properties"]["name"]}.json', 'w') as outfile:
        outfile.write(json.dumps(exclusion_set_info)+'\n')
        for exclusion in exclusion_set_data:
            outfile.write(json.dumps(exclusion)+'\n')
        print(f"{exclusion_set_info['properties']['name']}.json has been created in the current directory.")

def export_to_csv(exclusion_set_data, exclusion_set_info):
    """
    Export an exclusion set to a csv file in the local directory
    :param exclusion_set_data All data for an exclusion set, including all exclusions
    :param exclusion_set_info Dictionary with name, guid and operatingSystem of an exclusion set
    """
    with open(f'{exclusion_set_info["properties"]["name"]}.csv', 'w') as outfile:
        outfile.write("ExclusionGUID,Exclusion Type,Path,File Extension,Any Drive,FileScanEngine,FileScanChild,MAP,BP,SPP,Process Path,Process SHA\n")
        for exclusion in exclusion_set_data:
            guid = exclusion.get("guid", "")
            exclusionType = exclusion.get("exclusionType", "")
            path = exclusion.get("path", "")
            fileExtension = exclusion.get("fileExtension", "")
            anyDrive = str(exclusion.get("anyDrive", "")).replace("None", "")
            fileScan = str(exclusion.get("engineSettings", {}).get("fileScan", {}).get("applyToEngine", "")).replace("False", "")
            fileScanChild = str(exclusion.get("engineSettings", {}).get("fileScan", {}).get("applyToChildProcesses", "")).replace("False", "")
            MAP = str(exclusion.get("engineSettings", {}).get("maliciousActivity", {}).get("applyToEngine", "")).replace("False", "")
            bp = str(exclusion.get("engineSettings", {}).get("behavioralProtection", {}).get("applyToEngine", "")).replace("False", "")
            spp = str(exclusion.get("engineSettings", {}).get("systemProcessProtection", {}).get("applyToEngine", "")).replace("False", "")
            processPath = exclusion.get("process", {}).get("path", "")
            processSHA = exclusion.get("process", {}).get("sha", "")
            outfile.write(f"{guid},{exclusionType},{path},{fileExtension},{anyDrive},{fileScan},{fileScanChild},{MAP},{bp},{spp},{processPath},{processSHA}\n")
    print(f"{exclusion_set_info['properties']['name']}.csv has been created in the current directory.")

def json_or_csv():
    """
    Choose output format of json or csv
    :return choice Selected string representation of 1 or 2
    """
    print("[1] - CSV")
    print("[2] - JSON")
    choice = input("Do you want the output in JSON or CSV? ")
    if choice == '1' or choice == '2':
        return choice
    else:
        print("Choice must be 1 or 2.  Try again")
        json_or_csv()

def process_all(exclusion_sets, se_access_token, org_id):
    """
    Process all exclusion sets into a json or csv file
    :param exclusion_sets List of exclusion sets
    :param se_access_token Secure Endpoints access token
    :param org_id Organization ID of the chosen organization
    """
    # Get data for all exclusion sets and save to file
    choice = json_or_csv()
    for exclusion_set in exclusion_sets:
        exclusion_set_data = get_exclusion_set_data(se_access_token, org_id, exclusion_set)
        if choice == '1':
            export_to_csv(exclusion_set_data, exclusion_set)
        elif choice == '2':
            export_to_json(exclusion_set_data, exclusion_set)
    exit("Processing complete")

if __name__ == "__main__":

    # Get access tokens
    se_access_token = get_se_access_token()

    # Get org ID
    org_id = get_organization_id(se_access_token)

    # Get exclusion sets
    exclusion_sets = get_exclusion_sets(se_access_token, org_id)

    # Get a specific exclusion set guid
    exclusion_set_info = select_exclusion_set(exclusion_sets, se_access_token, org_id)

    # Pull exclusions using the org_id and exclusion_set guid
    exclusion_set_data = get_exclusion_set_data(se_access_token, org_id, exclusion_set_info)

    # Choose data output format
    format = json_or_csv()

    # Export data to file in json or csv format
    if format == '1':
        export_to_csv(exclusion_set_data, exclusion_set_info)
    elif format == '2':
        export_to_json(exclusion_set_data, exclusion_set_info)
