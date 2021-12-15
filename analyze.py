import requests
import json


class Analyzer:
    def __init__(self, apikey):
        self.apikey = apikey
        
        with open('results.json', 'r') as file:
            self.json = json.loads(file.read())
            file.close()
    
    def getfilereport(self, id):
        url = "https://www.virustotal.com/api/v3/files/" + id
        headers = {
            "Accept": "application/json",
            "x-apikey": self.apikey
        }
        
        response = requests.request("GET", url, headers=headers)

        return json.loads(response.text)
    
    

if __name__ == "__main__":
    analyze = Analyzer("your VT API Key here")
    

    
    # Get File Scan
    filescan = analyze.getfilereport("564ab8c4e85be79b294c730a783490c743c6e3cbdd0014f2895ae0f761fc303e")
    #print(filescan["data"]["attributes"]["last_analysis_results"]["Gridinsoft"]["category"])
    for av in filescan["data"]["attributes"]["last_analysis_results"]:
        if filescan["data"]["attributes"]["last_analysis_results"][av]["category"] == "malicious":
            print(av + ":" + filescan["data"]["attributes"]["last_analysis_results"][av]["category"])
            analyze.json[av] += 1
    
    # Write info
    with open('results.json', 'w') as file:
        
        file.write(str(analyze.json).replace("'", '"'))
        file.close()
    