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
    # Reading the "secret.json" file for finding its key
    with open('secret.json', 'r') as file:
        _r = json.loads(file.read())
        file.close()
    
    # Scan
    analyze = Analyzer(_r["apiKey"])
    
    # Read Stats
    with open('stats.json', 'r') as file:
        rl = json.loads(file.read())
        file.close()

    
    # Get File Scan
    filescan = analyze.getfilereport(input('Scan ID: '))
    if not filescan["data"]["attributes"]["sha256"] in rl["testedHashes"]:
        #print(filescan["data"]["attributes"]["last_analysis_results"]["Gridinsoft"]["category"])
        for av in filescan["data"]["attributes"]["last_analysis_results"]:
            if filescan["data"]["attributes"]["last_analysis_results"][av]["category"] == "malicious":
                print(av + ":" + filescan["data"]["attributes"]["last_analysis_results"][av]["category"])
                analyze.json[av] += 1
    
        # Write info
        with open('results.json', 'w') as file:
            
            file.write(str(analyze.json).replace("'", '"'))
            file.close()
        
        # Writing Stats

        with open('stats.json', 'w') as file:
            rl["testedSamples"] += 1
            rl["testedHashes"].append(filescan["data"]["attributes"]["sha256"])
            file.write(str(rl).replace("'", '"'))
            file.close()
    else:
        print('File already scanned.')
        exit()