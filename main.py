import typer
import os
from rich.console import Console
from rich.text import Text
from rich.progress import track
from rich import print
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from dotenv import find_dotenv, load_dotenv
import analyze_basic
import inspect_macho
import vt_upload

dotenv_path = find_dotenv()
load_dotenv(dotenv_path)
API_KEY = os.getenv("VT_API_KEY")

app = typer.Typer()

# ASCII art and welcome message.
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
        console.print("Use '--help' to view all available commands, or 'info' to get a basic rundown on how Infekja works and its background (e.g: 'python3 main.py --help').")

# FIRST COMMAND: "Info". Basic intro to the tool. Has optional '-vt' flag

@app.command()
def info(vt: bool = typer.Option(False, "-vt")):
    """
    Basic overview, functions, and background of Infekja. Optional flags: '-vt'.
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

    console.print("About", style="bold") #REMINDER update readme txt
    console.print("Derived from the Bosnian words infection ('infekcija') and apple ('jabuka'), Infekja is a macOS Malware Analyzer CLI Tool designed to streamline and simplify the process of examining potentially malicious macOS malware. By utilizing native macOS commands to analyze files and software, and enriching the gathered information through tools like VirusTotal, Infekja helps assess the likelihood of malicious behavior. Use the 'analyze' command to get started!""")

# SECOND COMMAND: Setup.

@app.command()
def Setup():
    "Instructions for setting up your API Keys with Infekja (Recommended)"

    console.print("\nInfekja leverages VirusTotal and CTIX to enrich and analyze the sample being investigated. 🧙🏽\nYou will have to provide your own API Keys to utilize these features. Please refer to the README file for step by step instructions, or follow the steps below:\n", style="aquamarine1")
    console.print("Step One: Edit your '.env' file to include these values: VT_API_KEY = 'your_secret_key', CTIX_API_KEY = 'your_secret_key'", style="bold")
    console.print("\nStep Two: Save the changes to your '.env' file", style="bold")
    console.print("\nStep Three: All done 💯", style="bold") 

# THIRD COMMAND: "analyze". Used to analyze sus DMGs (tbd pkgs)
# Moved to own Python Module, "analyze_baisc.py"

app.add_typer(analyze_basic.app, name="")

# FOURTH COMMAND "Inspect": Used to inspect the direct sus binaries 
# Moved to own Python Module, "inspect_macho.py"

app.add_typer(inspect_macho.app, name="")

# 5th COMMAND "vt-upload": Used to upload files to VT  

app.add_typer(vt_upload.app, name="")
     
    
console = Console()

# Entry point
if __name__ == "__main__":
    app()
