# "analyze" command: Used to analyze sus DMGs (tbd pkgs)

import typer
import subprocess
import os
from rich.console import Console
from rich.text import Text
from rich.progress import track
from rich import print
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
import time
import vt
import requests
import json
from dotenv import find_dotenv, load_dotenv

console = Console()
app = typer.Typer()

dotenv_path = find_dotenv()
load_dotenv(dotenv_path)
API_KEY = os.getenv("VT_API_KEY")

@app.command()

def analyze(file_path: str):
    "Basic analysis against a DMG or PKG: 'python3 main.py analyze ~/Desktop/Malware/AMOS.dmg'"
    # Check if the file exists
    if not os.path.exists(file_path):
        typer.echo(f"Error: The file '{file_path}' does not exist!")
        raise typer.Exit(code=1)
    console.print(f"\n🔦 Analysis of: {file_path}\n", style="hot_pink2") #colors https://rich.readthedocs.io/en/stable/appendix/colors.html

    for i in track(range(2), description="Running cmds..."):
        time.sleep(0.3) # https://rich.readthedocs.io/en/stable/progress.html 

    # frankg suggestion on using "mdls" and specifying common metadata keys. ref https://developer.apple.com/documentation/coreservices/file_metadata/mditem/common_metadata_attribute_keys
    try:
        file_result = subprocess.run(["mdls", "-attr", "kMDItemContentType", "-attr", "kMDItemKind", "-attr", "kMDItemWhereFroms", file_path], capture_output=True, text=True, check=True)
        console.print("[bright_green]\nFile Type:", end= " ") # end ensures that the next line appears ON THE same line
        #typer.echo(file_result.stdout.split(" ", 1)[1]) old format for "file" cmd that was being used  
        typer.echo(file_result.stdout)
    
    except subprocess.CalledProcessError as e:
        typer.echo(f"Error running 'file' command: {e}")
        raise typer.Exit(code=1)
    
    # Generate a sha256 hash 
    try:
        sha256_hash_result = subprocess.run(["shasum", "-a", "256", file_path], capture_output=True, text=True, check=True)
        sha256_hash = sha256_hash_result.stdout.split(" ", 1)[0].strip()
        console.print("[bright_green]sha256 Hash:", end=" ")
        typer.echo(sha256_hash)

    except subprocess.CalledProcessError as e:
        typer.echo(f"Error computing sha256 hash: {e}")
        raise typer.Exit(code=1) 
        
    # Verify code signatures and integrity with the codesign utility (https://eclecticlight.co/2019/10/25/how-to-check-signatures-on-apps-installers-and-packages/)
    try:
        codesign_result = subprocess.run(["codesign", "-dvvvv", file_path], capture_output=True, text=True) #removed "check=true" due to non signed DMGs returning an error (non zero exit)
        filename = os.path.basename(file_path)
        cleaner_format = codesign_result.stderr.replace(file_path, filename)
        console.print("[bright_green]\nCodesigning Results:", end= " ")
        typer.echo(cleaner_format)
        #typer.echo(f"{codesign_result.stderr}") og note
        #codesign_result.returncode 
        # returncode=0 if object is signed
        # returncode=1 if object is not signed
        #typer.echo(f"{codesign_result}")
        if codesign_result.returncode == 1:
            print("❌ Object is NOT SIGNED\n")
        if codesign_result.returncode == 0:
            console.print("✅ Object is signed!\n")    

    except subprocess.CalledProcessError as e:
        typer.echo(f"Error computing codesigning result: {e}")
        raise typer.Exit(code=1) 
       
    # Apple notarization checks + potential details on why a signature was revoked (https://ss64.com/mac/spctl.html)

    try:
        spctl_result = subprocess.run(["spctl", "-a", "-vvvv", "-t", "install", file_path], capture_output=True, text=True)
        filename = os.path.basename(file_path)
        cleaner_format = codesign_result.stderr.replace(file_path, filename)
        console.print("[bright_green]Spctl Result:", end= " ")
        typer.echo(cleaner_format)
        #typer.echo(f"{spctl_result.stderr}") #this output works, need to clean up format to remove file path name REMINDER
        #console.print(spctl_result)
        # returncode=0 if object is accepted/passes checks
        # returncode=3 if object does not pass
        if spctl_result.returncode == 3:
            print("❌ Object is NOT Notarized or has a usuable signature\n")
        if codesign_result.returncode == 0:
            console.print("✅ Object is Notarized!\n")    

    except subprocess.CalledProcessError as e:
        typer.echo(f"Error computing spctl result: {e}")
        raise typer.Exit(code=1)

    # VirusTotal Lookup
    if sha256_hash_result and API_KEY:
            url = f"https://www.virustotal.com/api/v3/files/{sha256_hash_result.stdout.split(" ", 1)[0].strip()}"
            
            headers = {
                "accept": "application/json",
                "x-apikey": API_KEY
            }
            response = requests.get(url, headers=headers)
            response_data = response.json()

            console.print("VirusTotal Results ⬇️\n", style="bright_green")
            tags = response_data["data"]["attributes"]["tags"]
            first_submitted_date = response_data["data"]["attributes"]["first_submission_date"]
            last_submission_date = response_data["data"]["attributes"]["last_submission_date"]
            type_extension = response_data["data"]["attributes"]["type_extension"]
            real_link = response_data["data"]["id"]
            latest_analysis_stats = response_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            meaningful_name = response_data["data"]["attributes"]["meaningful_name"]
            community_score = response_data["data"]["attributes"]["reputation"]
            #popular_threat_name = response.data["popular_threat_classification"]["popular_threat_name"]

            # Convert to users local time 
            first_submitted_date = time.strftime('%Y-%m-%d', time.localtime(first_submitted_date))
            last_submission_date= time.strftime('%Y-%m-%d', time.localtime(last_submission_date)) 

            console.print(f"Name: {meaningful_name}")
            console.print(f"Tags: {tags}")
            print("First Submitted Date", first_submitted_date)
            print("Last Submitted Date", last_submission_date)
            print(f"File Type: {type_extension}")
            print(f"Malicious Verdict: {latest_analysis_stats}")
            print(f"Community Score: {community_score}")
            #print(f"Popular Threat Name: {popular_threat_name}")
            print(f"URL: https://www.virustotal.com/gui/file/{real_link}\n")  
    else:
        console.print("No 'VT_API_KEY' Found! Consider adding it to get the most out of Infekja. See 'setup' for more information\n")    
        return    
    
# Invokes the "dropped_files" relatoinship. https://docs.virustotal.com/reference/files-relationships

    console.print("[bright_red]VirusTotal dropped_files -> sigma_rules Pivot 👀 \nFor more inforrmation on this function, invoke the 'info -vt' flag\n") #REMINDER CREATE THIS FLAG

    #if sha256_hash_result and API_KEY:
    if API_KEY:

            url = f"https://www.virustotal.com/api/v3/files/{sha256_hash_result.stdout.split(" ", 1)[0].strip()}/dropped_files?limit=10"

            headers = {
                "accept": "application/json",
                "x-apikey": API_KEY
            }
           
            response = requests.get(url, headers=headers)
            response_data = response.json()

    sigma_results_1 = [] #added these because I was running into a unboundlocalerror. Get feedback if this is best practice
    sigma_results_2 = []

    if "data" in response_data and response_data["data"]: #REMINDER. This format pulls "sections" from the overall JSON "dropped_files" output. Just call which field you need
        attributes_1 = response_data["data"][0].get("attributes", {})
        dropped_file_name = attributes_1.get("meaningful_name")
        sigma_results_1 = attributes_1.get("sigma_analysis_results", [])
        
    if len(response_data["data"]) > 1:
        attributes_2 = response_data["data"][1].get("attributes", {})
        dropped_file_name_2 = attributes_2.get("meaningful_name", "Unknown file name")
        sigma_results_2 = attributes_2.get("sigma_analysis_results", [])   

    if sigma_results_1 or sigma_results_2:
        typer.confirm(f"Sigma rules have been detected for files dropped in connection with {file_path}. Would you like to review them?", abort=True)
        console.print(f"\n[bright_red]First Dropped File with associated Sigma Rules:", end=" ")
        typer.echo(f"{dropped_file_name}\n")
        console.print(sigma_results_1 if sigma_results_1 else "No Sigma rules for this file.")

    # Second Dropped File output
        console.print(f"\n[bright_red]Second Dropped File with associated Sigma Rules:", end=" ")
        typer.echo(f"{dropped_file_name_2}\n")
        console.print(sigma_results_2 if sigma_results_2 else "No Sigma rules for this file.")
        #console.print("\nOnly the first two Dropped Files and assocaited Sigma rules are displayed. Would you like to view the entire 'dropped_files' response?\n")
        typer.confirm("\nOnly the first two Dropped Files and related Sigma Rules are shown. Would you like to view the entire 'dropped_files' response? (Warning: Output might be large)\n", abort=True) # REDMINER: Function to download this file to users desktop?
        console.print(response_data)
    else:
        console.print("No 'Dropped Files' associated with Sigma Rules found!\n")
