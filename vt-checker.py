import csv
import requests

def VT_Check():
    try:
        global detect_status
        url = 'https://www.virustotal.com/api/v3/files/' + hash
        header = {'x-apikey': API_key}
        response = requests.get(url, headers=header).json()
        detect_status = response['data']['attributes']['last_analysis_results']['CrowdStrike']['category']
        #print(detect_status)
    except Exception as ex:
        print(ex)

try:
    API_key = '--YOUR VIRUS TOTAL API KEY'
    location = input("Provide Hash List: ")
    if API_key == '':
        API_key = input("Enter VT API Key: ")

    with open('RESULTS.csv','w') as output:
        with open(location) as csv_file:
            output_data = csv.writer(output,delimiter=',')
            input_data = csv.reader(csv_file,delimiter=',')
            line_count = 0
            for row in input_data:
                if line_count == 0:
                    row.append('Falcon Status')
                    output_data.writerow(row)
                    line_count +=1
                else:
                    hash = row[0]
                    VT_Check()
                    row.append(detect_status)
                    output_data.writerow(row)
                    line_count +=1
except Exception as ex:
    print(ex)

