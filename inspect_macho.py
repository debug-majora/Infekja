# "Inspect" command: Used to inspect the direct sus binaries 

import typer
import subprocess
import os
from rich.console import Console
from rich.text import Text
from rich.progress import track
from rich import print
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
def inspect(file_path: str):
    "Basic analysis against a Macho File: Single or Universal (fka 'Fat')"
    # Check if the file exists
    if not os.path.exists(file_path):
        typer.echo(f"Error: The file '{file_path}' does not exist!")
        raise typer.Exit(code=1)
    console.print(f"\n🔦 Analysis of: {file_path}\n", style="hot_pink2")
    for i in track(range(2), description="Thinking in 0s and 1s..."):
        time.sleep(0.3)

#runs the "file" command

    try:
        inspect_result = subprocess.run(["file", file_path], capture_output=True, text=True, check=True)
        console.print("[bright_green]\nFile Type:", end= " ")
        console.print(inspect_result.stdout)
        
    except subprocess.CalledProcessError as e:
        typer.echo(f"Error running 'file' command: {e}")
        raise typer.Exit(code=1) 
        
    # Generate a sha256 hash 
    try:
        sha256_hash_result = subprocess.run(["shasum", "-a", "256", file_path], capture_output=True, text=True, check=True)
        console.print("[bright_green]sha256 hash:", end= " ")
        typer.echo(sha256_hash_result.stdout.split(" ", 1)[0].strip())

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

        if spctl_result.returncode == 3:
            print("❌ Object is NOT Notarized or has a usuable signature\n")
        if codesign_result.returncode == 0:
            console.print("✅ Object is Notarized!\n")    

    except subprocess.CalledProcessError as e:
        typer.echo(f"Error computing spctl result: {e}")
        raise typer.Exit(code=1)
    
     # Run the 'otool -hv' command.    
    try:
        test_macho_output = subprocess.run(["otool", "-h", "-v", file_path], capture_output=True)
        console.print("[bright_green]macho_header result:", end= " ")
        typer.echo(test_macho_output.stdout)

    except subprocess.CalledProcessError as e:
        typer.echo(f"Error computing the Mach-O binary header: {e}")
        raise typer.Exit(code=1)    
    
    # Leverages the "strings" cmd
    '''try:
        ascii_strings = subprocess.run(["strings", "-", file_path], capture_output=True)
        #console.print(ascii_strings.stdout)
        output_path = os.path.expanduser("~/Desktop/strings.txt")
        with open(output_path, "w") as outfile:
            outfile.write(ascii_strings.stdout)

        console.print("[bright_green]Strings Results saved to Desktop:", end= " ")
        
    except subprocess.CalledProcessError as e:
        typer.echo(f"Error computing the Strings output: {e}")
        raise typer.Exit(code=1)  '''  
    
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
            real_link = response_data["data"]["id"]
            latest_analysis_stats = response_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            meaningful_name = response_data["data"]["attributes"]["meaningful_name"]
            community_score = response_data["data"]["attributes"]["reputation"]
            first_submitted_date = time.strftime('%Y-%m-%d', time.localtime(first_submitted_date))
            last_submission_date= time.strftime('%Y-%m-%d', time.localtime(last_submission_date)) 

            console.print(f"Name: {meaningful_name}")
            console.print(f"Tags: {tags}")
            print("First Submitted Date", first_submitted_date)
            print("Last Submitted Date", last_submission_date)
            print(f"Malicious Verdict: {latest_analysis_stats}")
            print(f"Community Score: {community_score}")
            print(f"URL: https://www.virustotal.com/gui/file/{real_link}\n")
    else:
        console.print("No 'VT_API_KEY' Found! Consider adding it to get the most out of Infekja. See 'setup' for more information\n")    
        return  
