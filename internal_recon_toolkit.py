from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
import os
import subprocess
import time

console = Console()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def prepare_output_dirs(base_dir):
    sub_dirs = ["subnet-discover-phase", "host-discover-phase", "enumeration-phase"]
    paths = {}
    for name in sub_dirs:
        path = os.path.join(base_dir, name)
        os.makedirs(path, exist_ok=True)
        paths[name] = path
    return paths

# Global configuration variables
config = {
    "output_dir": None,
    "subnet_discovery_target": None,
    "merged_subnets_file": None
}

def print_global_info(phase=None):
    output_info = f"[green]{config['output_dir']}[/green]" if config["output_dir"] else "[red]Not set[/red]"
    merged_info = f"[green]{config['merged_subnets_file']}[/green]" if config["merged_subnets_file"] else "[red]Not set[/red]"

    console.print()
    console.print(f"[bold]Output Folder:[/] {output_info}")
    console.print(f"[bold]Combined Subnet File:[/] {merged_info}")

    if phase == "subnet-discovery" or phase is None:
        subnet_info = f"[green]{config['subnet_discovery_target']}[/green]" if config["subnet_discovery_target"] else "[red]Not set[/red]"
        console.print(f"[bold]Subnet for Discovery:[/] {subnet_info}")
    console.print()

def set_config_menu():
    while True:
        clear_screen()
        console.print(Panel(Text("SET CONFIGURATION", style="bold blue"), expand=False))
        print_global_info()
        console.print("[yellow][1][/yellow] Set Output Folder")
        console.print("[yellow][2][/yellow] Set Subnet for Subnet Discovery")
        console.print("[yellow][3][/yellow] Set Merged Subnet File Path")
        console.print("[red][0][/red] Return to Main Menu")

        console.print()
        choice = Prompt.ask("[green]Select an option[/green]", choices=["0", "1", "2", "3"], default="0")

        if choice == "1":
            config["output_dir"] = Prompt.ask("[green]Enter output folder path[/green]", default="output")
        elif choice == "2":
            console.print(Panel(Text("Running Nmap Ping Scan - discovering live hosts...", style="bold cyan"), expand=False))
            console.print("    [dim]Common choices:[/dim]")
            console.print("    - 10.0.0.0/8")
            console.print("    - 172.16.0.0/12")
            console.print("    - 192.168.0.0/16")
            config["subnet_discovery_target"] = Prompt.ask("[green]Enter subnet for discovery (CIDR)[/green]", default="10.0.0.0/8")
        elif choice == "3":
            console.print(Panel(Text("Running Netdiscover - using ARP to identify live hosts...", style="bold cyan"), expand=False))
            config["merged_subnets_file"] = Prompt.ask("[green]Enter path to merged subnet file[/green]", default="subnet-discover-phase/all-unique-subnets.txt")
        elif choice == "0":
            break

from rich.text import Text

def discover_subnets_menu(phase_dirs):
    clear_screen()
    console.print(Panel(Text("DISCOVER POSSIBLE SUBNETS", style="bold yellow"), expand=False))
    print_global_info("subnet-discovery")
    console.print("[yellow][1][/yellow] Run Masscan")
    console.print("[yellow][2][/yellow] Run Nmap Ping Scan")
    console.print("[yellow][3][/yellow] Run Netdiscover")
    console.print("[yellow][4][/yellow] Run NBTSCan")
    console.print("[yellow][5][/yellow] Merge Discovered Subnets")
    console.print("[yellow][6][/yellow] View Merged Subnet File")
    console.print("[red][0][/red] Return to Main Menu")

    console.print()
    choice = Prompt.ask("[green]Select an option[/green]", choices=["0", "1", "2", "3", "4", "5", "6"], default="0")

    if choice == "0":
        return
    elif choice == "1":
        console.print(Panel(Text("Running Masscan - discovering hosts with open ports...", style="bold cyan"), expand=False))
        from rich.progress import track

        subnet = config["subnet_discovery_target"]
        subnet_dir = os.path.join(phase_dirs["subnet-discover-phase"], subnet.replace('/', '_'))
        os.makedirs(subnet_dir, exist_ok=True)
        masscan_out = os.path.join(subnet_dir, "masscan-out.txt")
        unique_out = os.path.join(subnet_dir, "unique-subnets-masscan.txt")

        ports = Prompt.ask("[green]Enter ports to scan (comma-separated)[/green]", default="22,443,445")
        rate = Prompt.ask("[green]Enter Masscan rate[/green]", default="1000")

        start = time.time()
        cmd = ["sudo", "masscan", subnet, f"-p{ports}", "--rate", rate]
        with open(masscan_out, "w") as f:
            for line in f:
                console.print(line.strip())
            proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.DEVNULL)
            proc.wait()
        end = time.time()
        console.print(f"[cyan]Masscan scan completed in {end - start:.2f} seconds[/cyan]")

        found = set()
        with open(masscan_out) as f:
            for line in f:
                if "Discovered" in line:
                    ip = line.split()[5]
                    subnet = ".".join(ip.split('.')[:3]) + ".0/24"
                    if subnet not in found:
                        found.add(subnet)
        with open(unique_out, "w") as uf:
            for subnet in sorted(found):
                uf.write(subnet + "")
        console.print(f"[green]Masscan results saved to: {masscan_out}[/green]")
    elif choice == "2":
        subnet = config["subnet_discovery_target"]
        subnet_dir = os.path.join(phase_dirs["subnet-discover-phase"], subnet.replace('/', '_'))
        os.makedirs(subnet_dir, exist_ok=True)
        nmap_out = os.path.join(subnet_dir, "nmap-out.txt")
        unique_out = os.path.join(subnet_dir, "unique-subnets-nmap.txt")

        start = time.time()
        cmd = ["sudo", "nmap", "-n", "-sn", subnet, "-oG", nmap_out]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time()
        console.print(f"[cyan]Nmap scan completed in {end - start:.2f} seconds[/cyan]")

        found = set()
        with open(nmap_out, "r") as f:
            for line in f:
                if line.startswith("Host:"):
                    ip = line.split()[1]
                    sn = ".".join(ip.split('.')[:3]) + ".0/24"
                    found.add(sn)

        with open(unique_out, "w") as uf:
            for sn in sorted(found):
                uf.write(sn + "")
        console.print(f"[green]Nmap results saved to: {nmap_out}[/green]")
    elif choice == "3":
        subnet = config["subnet_discovery_target"]
        subnet_dir = os.path.join(phase_dirs["subnet-discover-phase"], subnet.replace('/', '_'))
        os.makedirs(subnet_dir, exist_ok=True)
        netdiscover_out = os.path.join(subnet_dir, "netdiscover-out.txt")
        unique_out = os.path.join(subnet_dir, "unique-subnets-netdiscover.txt")

        start = time.time()
        cmd = ["sudo", "netdiscover", "-r", subnet, "-P"]
        with open(netdiscover_out, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)
        end = time.time()
        console.print(f"[cyan]NBTSCan completed in {end - start:.2f} seconds[/cyan]")
        end = time.time()
        console.print(f"[cyan]Netdiscover scan completed in {end - start:.2f} seconds[/cyan]")

        found = set()
        with open(netdiscover_out) as f:
            for line in f:
                parts = line.strip().split()
                if parts and parts[0].count(".") == 3:
                    ip = parts[0]
                    sn = ".".join(ip.split('.')[:3]) + ".0/24"
                    found.add(sn)

        with open(unique_out, "w") as uf:
            for sn in sorted(found):
                uf.write(sn + "")
        console.print(f"[green]Netdiscover results saved to: {netdiscover_out}[/green]")
    elif choice == "4":
        console.print(Panel(Text("Running NBTSCan - probing NetBIOS for active devices...", style="bold cyan"), expand=False))
        subnet = config["subnet_discovery_target"]
        subnet_dir = os.path.join(phase_dirs["subnet-discover-phase"], subnet.replace('/', '_'))
        os.makedirs(subnet_dir, exist_ok=True)
        nbtscan_out = os.path.join(subnet_dir, "nbtscan-out.txt")
        unique_out = os.path.join(subnet_dir, "unique-subnets-nbtscan.txt")

        start = time.time()
        cmd = ["sudo", "nbtscan", "-r", subnet]
        with open(nbtscan_out, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)

        found = set()
        with open(nbtscan_out) as f:
            for line in f:
                parts = line.strip().split()
                if parts and parts[0].count(".") == 3:
                    ip = parts[0]
                    sn = ".".join(ip.split('.')[:3]) + ".0/24"
                    found.add(sn)

        with open(unique_out, "w") as uf:
            for sn in sorted(found):
                uf.write(sn + "")
        console.print(f"[green]NBTSCan results saved to: {nbtscan_out}[/green]")
    elif choice == "5":
        console.print("[yellow]Choose merge mode:[/yellow]")
        console.print("[yellow][1][/yellow] Merge all unique subnet files")
        console.print("[yellow][2][/yellow] Select sources to merge from")
        console.print()
        merge_mode = Prompt.ask("[green]Mode[/green]", choices=["1", "2"], default="1")

        subnet_phase_dir = phase_dirs["subnet-discover-phase"]
        all_files = []

        if merge_mode == "1":
            for root, _, files in os.walk(subnet_phase_dir):
                for f in files:
                    if f.startswith("unique-subnets-") and f.endswith(".txt"):
                        all_files.append(os.path.join(root, f))
        else:
            console.print("[yellow]Available sources: masscan, nmap, netdiscover, nbtscan[/yellow]")
            tools = Prompt.ask("[green]Enter tools to include (comma-separated)[/green]", default="masscan,nmap")
            selected = [t.strip() for t in tools.split(",")]
            for root, _, files in os.walk(subnet_phase_dir):
                for tool in selected:
                    file = f"unique-subnets-{tool}.txt"
                    if file in files:
                        all_files.append(os.path.join(root, file))

        merged = set()
        for file_path in all_files:
            with open(file_path, "r") as f:
                for line in f:
                    merged.add(line.strip())

        merged_file = os.path.join(subnet_phase_dir, "all-unique-subnets.txt")
        console.print(f"[cyan]Total unique subnets: {len(merged)}[/cyan]")
        with open(merged_file, "w") as out:
            for line in sorted(merged):
                out.write(line + "")

        config["merged_subnets_file"] = os.path.abspath(merged_file)
        console.print(f"[green][✓] File 'all-unique-subnets.txt' was created in: {os.path.abspath(merged_file)}[/green]")

        input("Press Enter to return...")
    elif choice == "6":
        if config["merged_subnets_file"] and os.path.isfile(config["merged_subnets_file"]):
            console.print(Panel(Text("MERGED SUBNETS", style="bold magenta"), expand=False))
            with open(config["merged_subnets_file"], "r") as f:
                for line in f:
                    console.print(f"  {line.strip()}")
        else:
            console.print("[red]No merged subnet file is set or found.[/red]")
        input("Press Enter to return...")

    if choice == "0":
        return
    else:
        


        while True:
            clear_screen()
            console.print(Panel(Text("INTERNAL RECON TOOLKIT", style="bold cyan"), expand=False))
            print_global_info()
            console.print("[yellow][1][/yellow] Discover Possible Subnets")
            console.print("[yellow][2][/yellow] Host Discovery Phase [grey](coming soon)[/grey]")
            console.print("[yellow][3][/yellow] Enumeration Phase [grey](coming soon)[/grey]")
            console.print("[yellow][9][/yellow] Set Global Info")
            console.print("[red][0][/red] Exit")

            console.print()
            choice = Prompt.ask("[green]Enter your choice[/green]", choices=["0", "1", "2", "3", "9"], default="0")

            if choice == "1":
                if not config["output_dir"] or not config["subnet_discovery_target"]:
                    console.print("[bold red]Error: You must set the output folder and discovery subnet first.[/bold red]")
                    input("Press Enter to return...")
                    continue
                base_output_dir = config["output_dir"]
                os.makedirs(base_output_dir, exist_ok=True)
                phase_dirs = prepare_output_dirs(base_output_dir)
                discover_subnets_menu(phase_dirs)
            elif choice == "9":
                set_config_menu()
            elif choice == "0":
                console.print("[cyan]Exiting...[/cyan]")
                break
            else:
                console.print("[yellow]This phase is not implemented yet.[/yellow]")
                input("Press Enter to return to the main menu...")

def main_menu():
    while True:
        clear_screen()
        console.print(Panel(Text("INTERNAL RECON TOOLKIT", style="bold cyan"), expand=False))
        print_global_info()
        console.print("[yellow][1][/yellow] Discover Possible Subnets")
        console.print("[yellow][2][/yellow] Host Discovery Phase [grey](coming soon)[/grey]")
        console.print("[yellow][3][/yellow] Enumeration Phase [grey](coming soon)[/grey]")
        console.print("[yellow][9][/yellow] Set Global Info")
        console.print("[red][0][/red] Exit")

        console.print()
        choice = Prompt.ask("[green]Enter your choice[/green]", choices=["0", "1", "2", "3", "9"], default="0")

        if choice == "1":
            if not config["output_dir"] or not config["subnet_discovery_target"]:
                console.print("[bold red]Error: You must set the output folder and discovery subnet first.[/bold red]")
                input("Press Enter to return...")
                continue
            base_output_dir = config["output_dir"]
            os.makedirs(base_output_dir, exist_ok=True)
            phase_dirs = prepare_output_dirs(base_output_dir)
            discover_subnets_menu(phase_dirs)
        elif choice == "9":
            set_config_menu()
        elif choice == "0":
            console.print("[cyan]Exiting...[/cyan]")
            break
        else:
            console.print("[yellow]This phase is not implemented yet.[/yellow]")
            input("Press Enter to return to the main menu...")

if __name__ == "__main__":
    main_menu()
