# Juniper SRX Policy Parser

## Change notes for V4 
Added logical-systems policy support as it previously ignored it 

Added port lookup 


## Overview 

This tool parses Juniper firewall configuration files in the set style format and extracts the security policies with the resolved IP addresses and hostnames. 

## Workflow

There are two programs for this workflow 

1. juniper_policy_parser.py - built off of the original juniper policy parser script and enhanced with improved address mapping and set resolution.  
2. address_host_expander.py - expands the address sets and map the parsed CSV to a ppsm format output via csv. 

>NOTE
I did not combine these scripts to avoid having to make massive changes within variables and functionality which allows this to be relatively modular. 

---

## Scripts
### Juniper Policy Parser

Filename: juniper_policy_parser.py

Purpose: Converts Juniper security policies from set-format configuration files into a structured CSV. 

#### Steps

1. Convert the set conf docx files to a text file 
2. Move all setconf files to the setconf folder. 

3. Run the program via CLI with the setconf folder and the setconf_csv folder that will hold all the csv files created. 
   
```bash 
   python3 juniper_policy_parser.py -s <setconf_folder> -o <setconf_csv_folder>  
  ```
   

4. This will output csv file(s) in the formats of file `filename_setconf.txt.csv` inside of the setconf_csv folder


---
### Address Host Expander

Filename: address_host_expander.py 

Purpose:  This program is to take Juniper Policy Parser output and the set-configuration file and parse through the conf file to make a eMASS PPSM artifact. 

#### Steps 

1. Convert the `filename_conf.docx` to a text file as `filename_conf.txt` 
2. Move all conf files to the conf folder. 

2. Run the Address Host Expander program from cli
   ```bash
   python3 address_host_expander.py -s <setconf_csv_folder> -c <conf_folder> -o <ppsmoutput_folder>  
   ```
3. The output will be two csv files, filename.csv and filename_full.csv, inside of the ppsmoutput folder. 

The full csv file is without the character limit on the fields and will be the uploaded artifact, please export the csv with the 'full' for eMASS use. 

This will expand the address sets and map the parsed CSV to a PPSM friendly copy and paste format, additional data modification
may be required. 

This program has a built in parameter check to adhere to the eMASS parameter character limits. 

Import the formatted csv into an excel workbook the 'template-blank_ppsm.xlsx', copy the fields over. Delete the imported table. 
