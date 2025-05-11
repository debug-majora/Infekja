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
from dotenv import find_dotenv, load_dotenv

console = Console()
app = typer.Typer()

dotenv_path = find_dotenv()
load_dotenv(dotenv_path)
API_KEY = os.getenv("VT_API_KEY")

@app.command()  

def vt_upload(file_path: str):
    "Upload files to VirusTotal (32mb or less): 'python3 main.py vt-upload ~/Desktop/Malware/Sus.dmg'"
    if not os.path.exists(file_path):
        typer.echo(f"Error: The file '{file_path}' does not exist!")
        raise typer.Exit(code=1)
    console.print(f"\n🔦 Analysis of: {file_path}\n", style="hot_pink2")
    for i in track(range(2), description="Uploading to Virustotal.....\n"):
        time.sleep(0.3)

    if not API_KEY:
        console.print("No 'VT_API_KEY' Found! Consider adding it to get the most out of Infekja. See 'setup' for more information.")  
        raise typer.Exit(code=1)

    try:
        url = "https://www.virustotal.com/api/v3/files" 
        with open(file_path, "rb") as file:
            files = {"file": (file_path, file)}
            headers = {
                "accept": "application/json",
                "x-apikey": API_KEY
            }
            response = requests.post(url, files=files, headers=headers)
        print("Upload successful, fetching stats")  
        #print(response.text)  
    except subprocess.CalledProcessError as e:
        typer.echo(f"An error has occured, please try again: {e}")
        raise typer.Exit(code=1) 
    
    # WHERE I LEFT OFF: Fetching stats, need to pull from this API using ID https://docs.virustotal.com/reference/analysis