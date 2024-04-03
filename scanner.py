import argparse
from datetime import datetime
import os
from rich import print as rich_print
from openai import OpenAI
import time
from tqdm import tqdm
from textwrap import wrap
from rich.console import Console

# Initialize OpenAI client
console = Console()
client = OpenAI(base_url="http://localhost:1234/v1", api_key="not-needed")

def analyze_security(content):
    completion = client.chat.completions.create(
        model="local-model",  # field is not currently used in LM studio
        messages=[
            {"role": "system", "content": "Scan the provided code chunk for security vulnerabilities - there is a high chance there are no vulnerabilities in the code. You MUST separate each security issue identified with the characters @@@@. Only respond with 'FALSE' if there are no vulnerabilities. If a security vulnerability is present, respond with 'TRUE' then the line numbers where the issue is identified, followed by the issue type in concise wording, and then finally the vulnerable code snippet but very concise. The response should be in the following format: TRUE | line_number(s) | issue_type | code_snippet."},
            {"role": "user", "content": content}
        ],
        temperature=0.7,
    )
    return completion.choices[0].message

def save_results_to_file(filepath, scan_results):
    with open(filepath, 'a') as file:
        for result in scan_results:
            file.write(' | '.join(result) + "\n")

def scan_file(file_path, scan_results, directory):
    console.print(f"[bold blue]Scanning[/bold blue]: {file_path}")
    with open(file_path, 'r') as file:
        content = file.readlines()

    total_chunks = (len(content) - 1) // 100 + 100
    file_scan_results = []

    for chunk_start in range(0, len(content), 100):
        chunk_end = min(chunk_start + 100, len(content))
        code_chunk = ''.join(content[chunk_start:chunk_end])
        response = analyze_security(code_chunk)

        if hasattr(response, 'content'):
            results = response.content
        elif isinstance(response, dict) and 'content' in response:
            results = response['content']
        else:
            results = response

        if results:
            # Split the result into individual issues using "@@@@", it can be unreliable depending on the output of the model
            individual_results = results.split('@@@@')
            for result in individual_results:
                if "TRUE" in result:
                    try:
                        _, line_numbers, issue_description, code_snippet = result.split(' | ', 3)
                        adjusted_line_numbers = line_numbers.strip()
                        issue_description = issue_description.strip()
                        code_snippet = code_snippet.strip()
                        file_scan_results.append((file_path, adjusted_line_numbers, issue_description, code_snippet))
                    except ValueError:
                        console.print(f"[bold red]Error parsing result:[/bold red] {result}")
                        continue

    # Append this file's results to the main scan_results
    # scan_results.extend(file_scan_results)

    for file_path, line_numbers, issue_description, code_snippet in file_scan_results:
        console.print(f"[bold yellow]{file_path}[/bold yellow] | [bold magenta]Line: {line_numbers}[/bold magenta] | [bold green]{issue_description}[/bold green] | [bold cyan]{code_snippet}[/bold cyan]")

    console.print("")

    return file_scan_results

def scan_directory(directory, file_types=None, scan_all=False):
    if scan_all:
        files_to_scan = [os.path.join(root, file) for root, _, files in os.walk(directory)]
    else:
        files_to_scan = [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files if any(file.endswith(ft) for ft in file_types)]

    console.print(f"[bold magenta]Total files to scan:[/bold magenta] {len(files_to_scan)}")

    # Saving results to file
    scan_results = []
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_results_{timestamp}.txt"
    directory = "./"
    filepath = os.path.join(directory, filename)
    console.print(f"[bold green]Results saved to:[/bold green] {filepath}")

    for file_path in tqdm(files_to_scan, desc="Scanning files"):
        file_scan_results = scan_file(file_path, scan_results, directory)
        save_results_to_file(filepath, file_scan_results)

def main():
    # Start the timer
    start_time = time.time()
    
    parser = argparse.ArgumentParser(description="Scan source code for security issues.")
    parser.add_argument("directory", type=str, help="Directory to scan")
    parser.add_argument("--file-types", type=str, nargs="+", default=[".py"], help="File types to scan, e.g., .py .js")
    parser.add_argument("--all", action="store_true", help="Scan all files regardless of file type")
    args = parser.parse_args()
    
    # Pass scan_all to scan_directory function based on --all flag
    scan_directory(args.directory, args.file_types, scan_all=args.all)

    # Calculate the elapsed time and print it
    elapsed_time = time.time() - start_time
    console.print(f"[bold green]Finished scanning. Total time: {elapsed_time:.2f} seconds[/bold green]")

if __name__ == "__main__":
    main()
