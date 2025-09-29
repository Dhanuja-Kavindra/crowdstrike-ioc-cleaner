# crowdstrike-ioc-cleaner
Automated tool for cleaning CrowdStrike prevention lists using VirusTotal checks.

## Issue
Back in 2022, we faced an issue with the **CrowdStrike blacklist**. Due to a platform limitation, the maximum capacity was **4000 hashes**.  
Many of these entries were old IOCs that no longer needed to remain in the blacklist, as they were already being detected by CrowdStrike itself.  
We needed a way to clean up the list and only keep the IOCs that were not natively detected by CrowdStrike.

## Solution
To solve this problem, two Python scripts were developed:

### `cs-cleaner.py`
This script manages interaction with the CrowdStrike Falcon platform and the prevention list.  
It provides functions to:
1. Log in to a CrowdStrike CID using client ID and secret  
2. Select the relevant CID (an organization may have multiple Falcon environments)  
3. Download the entire prevention list from the selected CID  
4. Clean the prevention list based on results from the `vt-checker.py` script  

### `vt-checker.py`
This script checks hash values from the prevention list against **VirusTotal**.  
- It consumes the list created by the `savePreventionList()` function in `cs-cleaner.py`.  
- Each hash is checked for detection status by the **CrowdStrike Falcon engine** in VirusTotal.  
- If a hash is identified by the Falcon engine, the script marks it in the output file for later use in the cleaning process.  
- After saving this output, the hashes marked as malicious by Falcon can be filtered into a separate file and then fed back into `cs-cleaner.py` for removal.

## Flow
1. Login to the CrowdStrike platform using the login function in `cs-cleaner.py`  
2. Select the correct CID using the CID selection function in `cs-cleaner.py`  
3. Download the prevention list from the chosen CID using the download function in `cs-cleaner.py`  
4. Check the downloaded blacklist hashes in VirusTotal using `vt-checker.py`  
5. Using the results from `vt-checker.py`, remove unwanted IOCs from the CrowdStrike prevention list with the hash removal function in `cs-cleaner.py`  

```mermaid
flowchart TD
    A[Start] --> B[cs-cleaner.py: Login to CS (client ID & secret)]
    B --> C[cs-cleaner.py: Select correct CID]
    C --> D[cs-cleaner.py: Download prevention list]
    D --> E[vt-checker.py: Check hashes in VirusTotal (Falcon engine)]
    E --> F[Filter: keep hashes identified by Falcon]
    F --> G[cs-cleaner.py: Remove unwanted IOCs from prevention list]
    G --> H[End]
