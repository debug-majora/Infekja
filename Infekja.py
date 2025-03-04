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

dotenv_path = find_dotenv()
load_dotenv(dotenv_path)
API_KEY = os.getenv("VT_API_KEY")

app = typer.Typer()

# avoid red, green, blue, and yellow (when used together, not friendly to colorblind folks)

# ASCII art and welcome message. Replace with actual DART Darth Vader logo
def display_welcome_message():
    ascii_art = r"""
⠀⠀⠀⠀⠀⣠⣴⣶⣯⠪⣕⢶⣦⣔⢄⠀⠀
⠀⠀⠀⢀⣼⣿⣿⣿⣿⣧⡙⣧⢹⣿⣷⣇⠀
⠀⠀⠀⣸⣿⣿⣿⣿⡟⠛⢿⣾⢿⡟⠟⢛⡄⠀
⠀⠀⠀⣿⣿⣿⣿⢟⣯⢖⣒⣚⣭⠀⣣⣈⡨⣢⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⣿⣿⢏⡛⠱⢿⣧⣿⢿⡂⠻⠭⠿⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣰⣿⣿⡟⢼⣿⡶⡄⣴⣶⣶⠇⠀⢶⣶⡎⡗⠀
⠀⢠⣿⣿⣿⢇⣷⣭⣃⠈⠙⠁⣠⢟⡟⡷⡙⢸⣷⠃
⢀⣿⣿⠿⢟⣸⣷⠶⠯⠍⠀⡫⢬⣬⣤⣥⡅⣊⣿⣼
⡜⣫⣴⣿⣿⣿⠁⢰⣿⣿⣿⣿⣞⠿⢛⣵⣾⡿⠛⠁
⠙⠿⠿⠿⣿⣿⣼⣬⣿⣿⣿⣿⣿⣷⠟⠉⠁
    """
    typer.echo(ascii_art)
    console.print("Welcome to Infekja!", style="plum2")
    console.print("The macOS Malware Analyzer CLI Tool 🔬", style="bold")
    typer.echo("-" * 113)

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    "macOS Malware Analyzer CLI Tool"
    if ctx.invoked_subcommand is None:
        # Display welcome message if no command is provided
        display_welcome_message()
        console.print("Use '--help' to see available commands, or 'info' to get a basic rundown on how Infekja works, and its background.")

# FIRST COMMAND: "Info". Basic intro to the tool. Has optional '-vt' flag

@app.command()
def info(vt: bool = typer.Option(False, "-vt")):
    """
    Basic overview, functions, and background of Infekja. Optional flags include: -vt.
    """
    if vt:
        console.print("\nThe VirusTotal 'dropped_files' → 'sigma_rules' function uses the 'dropped_files' relationship string to identify files written to disk during VT sandbox execution. DMGs, PKGs or applications are merely containers for the malicious 'binaries' that are nested inside. Pivoting to the executed dropped files provides more accurate insights for analysis.\n")    
        table = Table(title="")
        table.add_column("Resources", justify="left", style="cyan", no_wrap=True)
        table.add_column("ITW Dropped File Samples", style="magenta")
        table.add_row("https://docs.virustotal.com/reference/files-relationships", "https://www.virustotal.com/gui/file/c302367a897191b5f8717b7f988df0d4096816f12d58d5e479bd3e5d30af8b82/detection")
        table.add_row("https://docs.virustotal.com/reference/dropped_files", "https://www.virustotal.com/gui/file/a3d06ffcb336cba72ae32e4d0ac5656400decfaf40dc28862de9289254a47698/detection")
        table.add_row("https://docs.virustotal.com/reference/files", "https://www.virustotal.com/gui/file/e596da76aaf7122176eb6dac73057de4417b7c24378e00b10c468d7875a6e69e")
        table.add_row("https://x.com/moonlock_lab/status/1892545279896719376")
        console.print(table)
        return
    
    console.print("\nInfekja 🦠 🍎\n", style="bold red")
    #console.print("\nInInfekja: Derived from the Bosnian words infection (infekcija) and apple (jabuka) 🦠 🍎\n", style="bold red")
    ascii_art_apple = r"""
             .:'
         __ :'__
      .'`  `-'  ``.
     :             :
     :             :
      :           :
  jgs  `.__.-.__.'
    """
    console.print("About", style="bold") #REMINDER update readme txt
    console.print("""Infekja is macOS Malware Analyzer CLI Tool designed to streamline and simplify the process of examining potentially malicious macOS malware. 
By utilizing native macOS commands to analyze files and software, and enriching the gathered information through tools like VirusTotal, Infekja helps assess the likelihood of malicious behavior. Check out the readme file for detailed information on how best leverage Infekja to aid in your analysis or use simply use the '--help' command to get started!\n""")
    console.print("Behind the Name", style="bold")
    console.print("Derived from the Bosnian words infection ('infekcija') and apple ('jabuka').")
   # typer.echo(ascii_art_apple)

# SECOND COMMAND: Setup.

@app.command()
def Setup():
    "Instructions for setting up your VirusTotal API Keys with Infekja (Recommended)"

    console.print("\nInfekja leverages VirusTotal, CTIX, and Tria.ge for enrichment analysis and querying of the sample under investigation. 🧙🏽\nYou will have to provide your own API Keys to utilize these features. Please refer to the README file for step by step instructions, or follow the steps below:\n", style="aquamarine1")
    console.print("Step One: Edit your '.env' file to include these values: VT_API_KEY = 'your_secret_key', CTIX_API_KEY = 'your_secret_key', TRIAGE_API_KEY = 'your_secret_key'", style="bold")
    console.print("\nStep Two: Save the changes to your '.env' file", style="bold")
    console.print("\nStep Three: All done 💯\n", style="bold")    

# THIRD COMMAND: "analyze". Used to analyze sus DMGs (tbd pkgs)

@app.command()

def analyze(file_path: str, p: bool = typer.Option(False, "-p")):
    "Basic analysis against a DMG or PKG: 'python3 infekja.py analyze ~/Desktop/Malware/AMOS.dmg'"
    # Check if the file exists
    if not os.path.exists(file_path):
        typer.echo(f"Error: The file '{file_path}' does not exist!")
        raise typer.Exit(code=1)
    console.print(f"\n🔦 Analysis of: {file_path}\n", style="hot_pink2") #colors https://rich.readthedocs.io/en/stable/appendix/colors.html

    #if p:
    #   print("heLP ME")

    for i in track(range(2), description="Running cmds..."):
        time.sleep(0.3) # https://rich.readthedocs.io/en/stable/progress.html 

    # Run the 'file' cmd. REMINDER include cond statement IF zlib format THEN likely DMG + expand with something else?
    # or maybe include in the 'resources" section? https://newosxbook.com/DMG.html 
    # final edit: frankg suggested using "mdls" and specifying common metadata keys. ref https://developer.apple.com/documentation/coreservices/file_metadata/mditem/common_metadata_attribute_keys
    try:
        file_result = subprocess.run(["mdls", "-attr", "kMDItemContentType", "-attr", "kMDItemKind", "-attr", "kMDItemWhereFroms", file_path], capture_output=True, text=True, check=True)
        console.print("[bright_green]\nFile Type:", end= " ") # end ensures that the next line appears ON THE same line
        #typer.echo(file_result.stdout.split(" ", 1)[1]) old format for "file" cmd that was being used  
        typer.echo(file_result.stdout)
    
    except subprocess.CalledProcessError as e:
        typer.echo(f"Error running 'file' command: {e}")
        raise typer.Exit(code=1)
    
    # Run the 'shasum' cmd.
    try:
        sha256_hash_result = subprocess.run(["shasum", "-a", "256", file_path], capture_output=True, text=True, check=True)
        console.print("[bright_green]sha256 Hash:", end= " ")
        typer.echo(sha256_hash_result.stdout.split(" ", 1)[0].strip())

    except subprocess.CalledProcessError as e:
        typer.echo(f"Error computing sha256 hash: {e}")
        raise typer.Exit(code=1) 

    except subprocess.CalledProcessError as e:
        typer.echo(f"Error computing sha256 hash: {e}")
        raise typer.Exit(code=1)    
    
    # Run the 'codesign -dvvv" command. 
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
       
    # Runs 'spctl -a -vvvv -t install' command. ss64.com/mac/spctl.html. More details on why signature was revoked 
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

    #VT Lookup
    #if API_KEY:
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

            # Convert to local time. ChatGPT'd converting UTC to users local time
            first_submitted_date = time.strftime('%Y-%m-%d', time.localtime(first_submitted_date))
            last_submission_date= time.strftime('%Y-%m-%d', time.localtime(last_submission_date)) 

            console.print(f"Name: {meaningful_name}")
            console.print(f"Tags: {tags}")
            print("First Submitted Date", first_submitted_date)
            print("Last Submitted Date", last_submission_date)
            #print(f"First Submitted Date: {first_submitted_date}")
            #print(f"Last Submitted Date: {last_submission_date}")
            print(f"File Type: {type_extension}")
            print(f"Malicious Verdict: {latest_analysis_stats}")
            print(f"Community Score: {community_score}")
            #print(f"Popular Threat Name: {popular_threat_name}")
            print(f"URL: https://www.virustotal.com/gui/file/{real_link}\n")  # use console.print "U" to make the link clickable REMINDER    
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

# FOURTH COMMAND "Inspect": Used to inspect the direct sus binaries 

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
        
    # Run the 'shasum' cmd.
    try:
        sha256_hash_result = subprocess.run(["shasum", "-a", "256", file_path], capture_output=True, text=True, check=True)
        console.print("[bright_green]sha256 hash:", end= " ")
        typer.echo(sha256_hash_result.stdout.split(" ", 1)[0].strip())

    except subprocess.CalledProcessError as e:
        typer.echo(f"Error computing sha256 hash: {e}")
        raise typer.Exit(code=1)    
    
    # Run the 'codesign -dvvv" command. 
    try:
        codesign_result = subprocess.run(["codesign", "-dvvvv", file_path], capture_output=True, text=True) #removed "check=true" due to non signed DMGs returning an error (non zero exit)
        filename = os.path.basename(file_path)
        cleaner_format = codesign_result.stderr.replace(file_path, filename)
        console.print("[bright_green]\nCodesigning Results:", end= " ")
        typer.echo(cleaner_format)
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
    
    # Runs 'spctl -a -vvvv -t install' command
    try:
        spctl_result = subprocess.run(["spctl", "-a", "-vvvv", "-t", "install", file_path], capture_output=True, text=True)
        filename = os.path.basename(file_path)
        cleaner_format = codesign_result.stderr.replace(file_path, filename)
        console.print("[bright_green]Spctl Result:", end= " ")
        typer.echo(cleaner_format)
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
    
     # Run the 'otool -hv' command.    
    try:
        test_macho_output = subprocess.run(["otool", "-h", "-v", file_path], capture_output=True)
        console.print("[bright_green]macho_header result:", end= " ")
        typer.echo(test_macho_output.stdout)

    except subprocess.CalledProcessError as e:
        typer.echo(f"Error computing the Mach-O binary header: {e}")
        raise typer.Exit(code=1)    
    

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

console = Console()

# Entry point
if __name__ == "__main__":
    app()