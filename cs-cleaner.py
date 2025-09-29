import requests
import csv
from xlwt import Workbook
import pandas as pd
#disableing http warnings
import urllib3
urllib3.disable_warnings()
import os.path

http_proxy = "http://127.0.0.1:8080"
https_proxy = "https://127.0.0.1:8080"

proxyDict = {"http": http_proxy,"https": https_proxy}

def csLogIn():

    #Requesting csrf token No 1
    data_set1 = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0'}
    session_1 = requests.session()
    response_1 = session_1.post("https://falcon.crowdstrike.com/api2/auth/csrf").json()
    csrf_token_1 = response_1['csrf_token']
    id_1 = session_1.cookies.get_dict()['id']

    #Requesting csrf token No 2
    set_cookie = { 'id':id_1}
    session_2 = requests.session()
    requests.utils.add_dict_to_cookiejar(session_2.cookies, set_cookie)
    session_2_headers = {'content-type':'application/json','User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0','x-csrf-token':csrf_token_1}
    session_2.headers.update(session_2_headers)
    creds = open('credentials.txt', 'r')
    user = str(creds.readline()).strip('\n')
    pw = str(creds.readline()).strip('\n')
    data_set2 = {'username':user,'password':pw,'use_csam':'true'}
    response_2 = session_2.post("https://falcon.crowdstrike.com/auth/login",json=data_set2, verify=False).json()
    csrf_token_2 = response_2['csrf_token']
    id_2 = session_2.cookies.get_dict()['id']

    #Requesting csrf token No 3
    set_cookie = {'id':id_2}
    session_3 = requests.session()
    requests.utils.add_dict_to_cookiejar(session_3.cookies, set_cookie)
    session_3_headers = {'content-type':'application/json','User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0','x-csrf-token':csrf_token_2}
    session_3.headers.update(session_3_headers)
    two_fa = input("Enter 2FA Code: ")
    data_set3 = {'username':'--YOUR CS USER NAME--','password':'--YOUR CS PASSWORD--','2fa':two_fa,'use_csam':'true'}
    response_3 = session_3.post("https://falcon.crowdstrike.com/auth/login",json=data_set3, verify=False).json()
    csrf_token_3 = response_3['csrf_token']
    id_3 = session_3.cookies.get_dict()['id']
    return csrf_token_3,id_3

def checkAvailableSites(ID):
    #Cheking Site Details
    set_cookie = {'id':ID}
    session_4 = requests.session()
    requests.utils.add_dict_to_cookiejar(session_4.cookies, set_cookie)
    session_4_headers = {'content-type':'application/json','x-cs-use-csam':'true','User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0'}
    session_4.headers.update(session_4_headers)
    data_set4 = {"checks":[{"action":"read","resource":"csrn:detect:api"},{"action":"read","resource":"csrn:falcon:audit-log"},{"action":"read","resource":"csrn:module:api"},{"action":"read","resource":"csrn:module:virus-total"},{"action":"read","resource":"csrn:quarantined-file:api"},{"action":"read","resource":"csrn:crowdscore:incident"},{"action":"read","resource":"csrn:falcon:device"},{"action":"read","resource":"csrn:graph:api"},{"action":"read","resource":"csrn:metadata:api"},{"action":"read","resource":"csrn:threat-graph:api"},{"action":"write","resource":"csrn:quarantined-file:api"},{"action":"view","resource":"csrn:remote-response:audit-log"},{"action":"read","resource":"csrn:host-firewall"},{"action":"read","resource":"csrn:ui:device-control-native-ui"},{"action":"read","resource":"csrn:eam:api"},{"action":"read","resource":"csrn:eam:device-control"},{"action":"read","resource":"csrn:ui:device-control"},{"action":"read","resource":"csrn:ui:containers"},{"action":"read","resource":"csrn:ui:eam:mobile"},{"action":"read","resource":"csrn:falcon:device-policy:prevention"},{"action":"read","resource":"csrn:falcon:device-group"},{"action":"upload","resource":"csrn:from-home:user-to-tags-mapping"},{"action":"read","resource":"csrn:falcon:download"},{"action":"read","resource":"csrn:provisioning-token"},{"action":"read","resource":"csrn:mobile-enrollment:enroll"},{"action":"read","resource":"csrn:device-policy:firewall"},{"action":"read","resource":"csrn:falcon:device-policy:sensor-update"},{"action":"read","resource":"csrn:custom-ioa:detection"},{"action":"read","resource":"csrn:falcon:device-policy:device-control"},{"action":"read","resource":"csrn:falcon:device-policy:remote-response"},{"action":"read","resource":"csrn:device-policy:store:airlock"},{"action":"read","resource":"csrn:device-policy:store:automox"},{"action":"read","resource":"csrn:device-policy:store:netskope"},{"action":"read","resource":"csrn:remote-response-v2:custom-scripts"},{"action":"read","resource":"csrn:remote-response-v2:put-files"},{"action":"read","resource":"csrn:falcon:device-policy:exclusions"},{"action":"read","resource":"csrn:prevention:hash"},{"action":"read","resource":"csrn:falcon:device:containment:ip-whitelist"},{"action":"read","resource":"csrn:mobile-mgmt:assigned-apps"},{"action":"read","resource":"csrn:overwatch:industry-trends"},{"action":"read","resource":"csrn:overwatch:detection-activity"},{"action":"read","resource":"csrn:overwatch:notifications"},{"action":"read","resource":"csrn:ui:discover"},{"action":"read","resource":"csrn:ui:discover-aws"},{"action":"read","resource":"csrn:ui:discover-cloud-workloads"},{"action":"read","resource":"csrn:spotlight:vulnerability"},{"action":"read","resource":"csrn:saved-filter:filter"},{"action":"write","resource":"csrn:saved-filter:filter"},{"action":"read","resource":"csrn:spotlight:vulnerability-report"},{"action":"read","resource":"csrn:intel:api"},{"action":"read","resource":"csrn:intel:actor"},{"action":"read","resource":"csrn:intel:news"},{"action":"read","resource":"csrn:intel:indicator"},{"action":"read","resource":"csrn:intel:tailored-intelligence"},{"action":"write","resource":"csrn:intel:sample-malware"},{"action":"write","resource":"csrn:intel:rfi:submission"},{"action":"read","resource":"csrn:falconx:reports:entities"},{"action":"read","resource":"csrn:intel:notification-subscription"},{"action":"write","resource":"csrn:binarly:search:fuzzy"},{"action":"write","resource":"csrn:binarly:search:exact"},{"action":"write","resource":"csrn:binarly:search:hunt"},{"action":"read","resource":"csrn:binarly:request"},{"action":"read","resource":"csrn:binarly:metadata"},{"action":"read","resource":"csrn:binarly:filetypes"},{"action":"read","resource":"csrn:binarly:download"},{"action":"list","resource":"csrn:auth:user:all"},{"action":"reset","resource":"csrn:auth:user:all:password"},{"action":"reset","resource":"csrn:auth:user:all:totp"},{"action":"read","resource":"csrn:store:app"},{"action":"read","resource":"csrn:intel:news:api"},{"action":"list","resource":"csrn:api-client"},{"action":"write","resource":"csrn:detect:api"},{"action":"download","resource":"csrn:extracted-file"},{"action":"write","resource":"csrn:falcon:device-policy:device-control"},{"action":"write","resource":"csrn:falcon:device-policy:exclusions"},{"action":"activate","resource":"csrn:remote-response-v2:commands:destructive"},{"action":"write","resource":"csrn:remote-response-v2:custom-scripts"},{"action":"read","resource":"csrn:remote-response:command-access"},{"action":"write","resource":"csrn:remote-response:command-access"},{"action":"read","resource":"csrn:spotlight:vulnerable-host"},{"action":"write","resource":"csrn:ui:device-control-native-ui"},{"action":"read","resource":"csrn:ui:insight"},{"action":"read","resource":"csrn:ui:mssp"},{"action":"read","resource":"csrn:ui:prevent"},{"action":"read","resource":"csrn:ui:prevent-for-home-use"},{"action":"write","resource":"csrn:falcon:audit-log"},{"action":"read","resource":"csrn:falcon:ui:all-branches"},{"action":"write","resource":"csrn:prevention:hash"},{"action":"view","resource":"csrn:ui:admin-trial-bar"}]}
    response_4 = session_4.post("https://falcon.crowdstrike.com/api2/auth/verify",json=data_set4, verify=False).json()
    csrf_token_4 = response_4['csrf_token']
    id_4 = session_4.cookies.get_dict()['id']
    sites = response_4['user_customers']
    print("Available CIDs :- "+str(sites))
    current_cid = str(response_4['customer'])
    print("Currently you are in :- "+current_cid+" CID")
    return csrf_token_4,id_4,current_cid


def cidChange(csrf_token,cookie_ID,CID):
    CID_change = input("Do you want to change the CID (y/n)?")
    if CID_change == 'y':
        site = input("Enter CID Number :-")
        set_cookie = {'id':cookie_ID}
        session_5 = requests.session()
        requests.utils.add_dict_to_cookiejar(session_5.cookies, set_cookie)
        session_5_headers = {'content-type': 'application/json', 'x-cs-use-csam': 'true','User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0','x-csrf-token': csrf_token}
        session_5.headers.update(session_5_headers)
        data_set5 = {'cid': site, 'use_csam': 'true'}
        response_5 = session_5.post("https://falcon.crowdstrike.com/api2/auth/switch-customer", json=data_set5, verify=False)
        id_5 = session_5.cookies.get_dict()['id']
        auth_info = checkAvailableSites(id_5)
        csrf_token_6 = auth_info[0]
        id_6 = auth_info[1]
        return csrf_token_6,id_6
    else:
        print("Proceeding with default CID " + CID)
        csrf_token_6 = csrf_token
        id_6 = cookie_ID
        return csrf_token_6,id_6

def savePreventionList(csrf_token,ID):
    set_cookie = {'id': ID}
    session_4 = requests.session()
    requests.utils.add_dict_to_cookiejar(session_4.cookies, set_cookie)
    session_4_headers = {'content-type': 'application/json','User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0','x-csrf-token': csrf_token}
    session_4.headers.update(session_4_headers)
    response_4 = session_4.get("https://falcon.crowdstrike.com/api2/csapi/tags/queries/hashes/v1?limit=0&offset=0&has_user_lists=true&scope=customer").json()
    hash_count = response_4['meta']['pagination']['total']
    print(str(hash_count)+" hashes in prevention list")
    print("Downloading Prevention list...")
    response_5 = session_4.get("https://falcon.crowdstrike.com/api2/csapi/tags/queries/hashes/v1?limit=" + str(hash_count) + "&offset=0&has_user_lists=true&scope=customer").json()
    hash_list = response_5['resources']
    print("Prevention list downloaded...")

    wb = Workbook()
    sheet = wb.add_sheet("Hashes")
    sheet.write(0,0,'Hash')
    for val in range(len(hash_list)):
        sheet.write(val+1,0,hash_list[val])

    wb.save('TestPreventionList.xls')
    data_xlsx = pd.read_excel('TestPreventionList.xls','Hashes',index_col=None)
    data_xlsx.to_csv('TestPreventionList.csv', encoding='utf-8',index=False)
    print(str(len(hash_list))+" hash values saved to TestPreventionList.csv")

def removeHash():
    login_para = csLogIn()
    auth_info = checkAvailableSites(login_para[1])
    auth_info = cidChange(auth_info[0],auth_info[1],auth_info[2])
    remove_list = input("Enter Hash List Name: ")
    set_cookie = {'id':auth_info[1]}
    session = requests.session()
    requests.utils.add_dict_to_cookiejar(session.cookies,set_cookie)
    session_headers = {'content-type':'application/json','User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0','x-csrf-token':auth_info[0]}
    session.headers.update(session_headers)


    with open('RemovedList.csv','w',newline='') as out_hash:
        with open(remove_list) as in_hash:
            input_hash = csv.reader(in_hash,delimiter=',')
            output_hash = csv.writer(out_hash,delimiter=',')
            line_count = 0

            for row in input_hash:
                if line_count == 0:
                    row.append('Removal Status')
                    output_hash.writerow(row)
                    line_count += 1
                    remove_status = ''
                else:
                    line_count +=1
                    hash = row[0]
                    response = session.get("https://falcon.crowdstrike.com/api2/csapi/tags/queries/hashes/v1?limit=20&offset=0&q="+str(hash)+"&has_user_lists=true&scope=customer").json()
                    #print("search response: "+str(response))
                    if response['meta']['pagination']['total'] == 1:
                        print("Hash "+str(hash)+" found in prevention list, starting deletion process.")
                        data_set = {'q':hash}
                        session_headers = {'content-type': 'application/x-www-form-urlencoded',
                                           'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0',
                                           'x-csrf-token': auth_info[0]}
                        session.headers.update(session_headers)
                        print("we are here")
                        #Below is the URI(request) we used to delete hashes.I have commented it for safe.
                        response = session.post("https://falcon.crowdstrike.com/api2/csapi/prevention/queries/hashes/DELETE/v1?scope=customer",data=data_set)
                        if response.status_code == 200:
                            remove_status = 'Deleted from prevention list'
                            row.append(remove_status)
                            output_hash.writerow(row)
                        else:
                           print("Failed to delete. Received response-> "+str(response))
                    else:
                        remove_status = 'Hash not found in prevention list'
                        row.append(remove_status)
                        output_hash.writerow(row)

                    print(str(line_count-1)+". Hash:"+hash+"|- Remove Status:- "+remove_status)

#----Select required function and comment rest----
#login_para = csLogIn()
#auth_info = checkAvailableSites(login_para[1])
#auth_info = cidChange(auth_info[0],auth_info[1],auth_info[2])
#savePreventionList(auth_info[0],auth_info[1])
removeHash()
