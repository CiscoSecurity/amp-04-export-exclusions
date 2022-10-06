# Setup
Update your .env file with CLIENT_ID and API_KEY from here:
https://developer.cisco.com/docs/secure-endpoint/#!authentication/4-generate-secure-endpoint-api-access-token
Also add CLOUD = <Cloud> (NAM, EU, APJC)

Example .env:
```
CLIENT_ID="client-abcde"
API_KEY="supersecretapikey"
CLOUD="NAM"
```

# Requirements

Python version 3.5+

Go through the [Authentication instructions](https://developer.cisco.com/docs/secure-endpoint/#!authentication) for SecureX to integrate Secure Endpoint and create an API Client. 

Install python requirements:
    pip install requests
    pip install python-dotenv

# Usage
When you first run the script you'll get authenticated and then presented with a list of organizations you belong to.

```
Which organization would you like to list exclusions from?
[1] - Org 1
[2] - Org 2
[3] - Org 3
Input a number listed above:
```

Choose a number from the list and you'll be presented with a list of exclusion sets for that organization and an option to export all lists.
    
```
Which exclusion set would you like to list exclusions from?
[1] - List 
[2] - Another list
[3] - Yet Another list
[4] - Oh Look another list
[5] - All exlcusion lists. NOTE: May be very time intensive depending on the volume.
Input a number listed above:
```

Choose the option for the list you want to export or all lists.
    
Next you're presented with an option for CSV or JSON.
    
```
[1] - CSV
[2] - JSON
Do you want the output in JSON or CSV?
```
    
Choose which you prefer and a file will be created in the local directory of the list you selected in the format you selected.
If you chose all lists, a file will be created for each list.    

```    
Oh Look another list.csv has been created in the current directory.
Processing complete
```
    
