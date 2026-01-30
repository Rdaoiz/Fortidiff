## Simplified Legacy Tool Readme 


## Info

- **Legacy_iid.py** is designed as an intake phase of all the IIDs within an audit.fvdl file from a scan to create a reference for all previous IIDs that are considered legacy. The output is a csv file I'd suggest you name based on the application you are running it on. 
-  **Legacy_new_findings.py** is designed to compare the list of IIDs in the csv file outputted against audit.fvdl files you are specifying. It has the ability to filter our lows, mediums, highs, crits, and also the ability to save notes to the report. 

## Usage 

**Legacy_iid.py** 

1. Place the audit fvdl files within a folder you want to establish a mock database with 
2. Run the legacy_iid.py program and provide the proper args in the format below. I advise you to name the output.csv to the application name that way you can have separate DBs. 
a. **For bulk handling** 
-- `python3 / python.exe legacy_iid.py <fvdl folder>  -o <application_name.csv>`
b. **For individual fvdl handling** 
-- `python3 / python.exe legacy_iid.py <fvdl file>  -o <application_name.csv>`

3. To add more fvdl files at another time you are able to add onto it by rerunning the individual fvdl handling command.

**NOTE** You can run it for bulk handling and then run for individual fvdl handling. Duplicate IIDs will be handled. 


**Legacy_new_findings.py**
1. Place the audit files into a folder, this will be used to for the comparison argument.  
2. Run the legacy_new_findings.py program and provide the proper args in the format below. I advise you to match the html report with the application for separate reports. 

a. **For bulk handling** 
-- `python3 / python.exe legacy_new_findings.py -c <application_name.csv> -p <post folder> -o <application_name.html>` `

b. **For individual fvdl handling** 
-- `python3 / python.exe legacy_new_findings.py -c <application_name.csv> -p <post file> -o application_name.html` 

3. If you are adding notes, there is a feature to save the notes so the report can be saved for later or shared. 
4. To add more fvdl files you are able to add onto it by rerunning the individual fvdl handling command.

**NOTE** You can run it for bulk handling and then run for individual fvdl handling. Duplicate IIDs are not handled. 
The reason I did not handle them is because the IID sometimes may cause issues when handling duplicates if IID migration is not on during a scan. 

To handle this I added the 'Post File' column so you can track what fvdl it is coming as the fvdl's have the date within the filename. This is intended to provide 
use to whoever is using this report. 


## Fortify Severity Calculation (Impact/Likelihood)

Both `legacy_iid.py` and `legacy_new_findings.py` now compute Fortify-style severity
using Impact and Likelihood (not the raw InstanceSeverity field). The logic mirrors
the Fortify Audit Workbench documentation:

- Likelihood = (Accuracy * Confidence * Probability) / 25
- Severity (risk quadrant):
  - Critical: Impact >= 2.5 and Likelihood >= 2.5
  - High: Impact >= 2.5 and Likelihood < 2.5
  - Medium: Impact < 2.5 and Likelihood >= 2.5
  - Low: Impact < 2.5 and Likelihood < 2.5

Implementation details:
- Impact, Probability, and Accuracy are read from RuleInfo/MetaInfo Group values in the FVDL.
- Confidence is read from Vulnerability/InstanceInfo/Confidence for each InstanceID.
- Likelihood is calculated from those values and then used with Impact to set severity.

References (official Fortify docs):
- Audit Workbench User Guide (Static Analysis Results Prioritization / Appendix):
  - Likelihood formula and sample risk calculations:
    https://help.sap.com/doc/audit-workbench-user-guide/24.2/en-US/AWB_Guide_24.2.0.pdf
- Fortify documentation (Estimating impact and likelihood with input from rules and analysis):
  - Defines 2.5 as the high/low threshold for impact and likelihood:
    https://www.microfocus.com/documentation/fortify-static-code-analyzer-and-tools/2540/awb-ugd-html-25.4.0/doc/2456_25.4.0/aff49859da86_estimateimpacklikelihood.html

