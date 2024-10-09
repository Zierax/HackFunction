import argparse
import json
import os
from dotenv import load_dotenv
import openai
from web3 import Web3
from slither import Slither
import requests
import tempfile
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

load_dotenv()  # Load environment variables from .env file

# Environment Variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
INFURA_API_KEY = os.getenv("INFURA_API_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

if not OPENAI_API_KEY or not INFURA_API_KEY or not ETHERSCAN_API_KEY:
    logging.error("API keys are missing. Ensure .env contains OPENAI_API_KEY, INFURA_API_KEY, and ETHERSCAN_API_KEY.")
    exit(1)

# Initialize Web3 instance
w3 = Web3(Web3.HTTPProvider(f"https://mainnet.infura.io/v3/{INFURA_API_KEY}"))

def scan_with_chatgpt(solidity_code):
    """Use ChatGPT to analyze Solidity code for vulnerabilities."""
    if not solidity_code.strip():
        logging.error("No Solidity code provided for analysis.")
        return "Error: No Solidity code provided."

    try:
        openai.api_key = OPENAI_API_KEY
        prompt = (
            "As a security expert specializing in Solidity smart contracts, "
            "your task is to thoroughly analyze the following Solidity code for potential vulnerabilities and security issues. "
            "Provide a detailed report highlighting any vulnerabilities, potential exploits, and suggestions for improvement.\n\n"
            "Solidity Code:\n"
            f"```solidity\n{solidity_code}\n```"
        )
        
        response = openai.Completion.create(
            model="gpt-3.5-turbo",
            prompt=prompt,
            max_tokens=1500,  # Increased token limit for more comprehensive analysis
            temperature=0.2,  # Slightly increased temperature for more diverse responses
            n=1,
            stop=None
        )
        
        # Check if the response has the expected structure
        if response and response.choices and len(response.choices) > 0:
            return response.choices[0].text.strip()
        else:
            logging.error("Unexpected response format from OpenAI API.")
            return "Error: Unexpected response format from ChatGPT."

    except openai.error.InvalidRequestError as e:
        logging.error(f"Invalid request to OpenAI API: {e}")
        return "Error: Invalid request to OpenAI API."
    except openai.error.AuthenticationError as e:
        logging.error(f"Authentication error with OpenAI API: {e}")
        return "Error: Authentication error with OpenAI API."
    except openai.error.APIConnectionError as e:
        logging.error(f"Network error while contacting OpenAI API: {e}")
        return "Error: Network error while contacting OpenAI API."
    except openai.error.OpenAIError as e:
        logging.error(f"OpenAI API error: {e}")
        return "Error: OpenAI API error."
    except Exception as e:
        logging.error(f"Unexpected error while analyzing with ChatGPT: {e}")
        return "Error: Unexpected error during analysis with ChatGPT."


def scan_with_slither(file_path):
    """Use Slither static analysis to detect vulnerabilities."""
    try:
        slither = Slither(file_path)
        vulnerabilities = []
        
        for detector in slither.detectors:
            for result in detector.results:
                vuln = {
                    "type": detector.name,
                    "description": result['description'],
                    "source": result['source_mapping'],
                }
                vulnerabilities.append(vuln)
        return vulnerabilities
    except Exception as e:
        logging.error(f"Slither analysis failed for {file_path}: {e}")
        return []

def fetch_contract_source(contract_address):
    """Fetch contract source code from Etherscan."""
    try:
        url = f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
        response = requests.get(url).json()

        if response.get("status") == "1" and response["result"]:
            return response["result"][0]["SourceCode"]
        return None
    except Exception as e:
        logging.error(f"Failed to fetch contract source from Etherscan: {e}")
        return None

def scan_solidity_file(file_path):
    """Perform static and GPT-based analysis on a single Solidity file."""
    try:
        with open(file_path, "r") as file:
            solidity_code = file.read()
        
        logging.info(f"Scanning {file_path} with Slither...")
        slither_vulns = scan_with_slither(file_path)
        
        logging.info(f"Scanning {file_path} with ChatGPT...")
        chatgpt_report = scan_with_chatgpt(solidity_code)
        
        return {
            "file": file_path,
            "slither": slither_vulns,
            "chatgpt": chatgpt_report
        }
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")
        return {"file": file_path, "error": str(e)}

def scan_solidity_contract_by_address(contract_address):
    """Fetch contract by address and perform analysis."""
    source_code = fetch_contract_source(contract_address)

    if not source_code:
        logging.error(f"Unable to fetch contract source for {contract_address}.")
        return None

    with tempfile.NamedTemporaryFile(suffix=".sol", delete=False) as temp_file:
        temp_file.write(source_code.encode())
        temp_file.flush()
        results = scan_solidity_file(temp_file.name)
    
    return results

def output_vulnerabilities(vulnerabilities, output_format="json"):
    """Format the vulnerability reports in JSON, XML, or CSV."""
    if output_format == "json":
        return json.dumps(vulnerabilities, indent=4)
    elif output_format == "xml":
        output = "<vulnerabilities>\n"
        for vuln in vulnerabilities:
            output += f"  <vulnerability type=\"{vuln['type']}\" description=\"{vuln['description']}\"/>\n"
        output += "</vulnerabilities>"
        return output
    elif output_format == "csv":
        output = "Type,Description\n"
        for vuln in vulnerabilities:
            output += f"{vuln['type']},{vuln['description']}\n"
        return output
    return ""

def find_solidity_files_in_directory(directory):
    """Recursively find all .sol files in a directory."""
    solidity_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".sol"):
                solidity_files.append(os.path.join(root, file))
    return solidity_files

def main():
    parser = argparse.ArgumentParser(description="SmartGuard Smart Contract Vulnerability Scanner")
    parser.add_argument("paths", nargs="+", help="Path to Solidity files, directories, or contract addresses")
    parser.add_argument("-o", "--output", help="Path and format for output file (e.g., output.json, output.xml, output.csv)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    all_results = []

    for path in args.paths:
        if os.path.isfile(path) and path.endswith(".sol"):
            logging.info(f"Scanning Solidity file: {path}")
            results = scan_solidity_file(path)
            all_results.append(results)
        elif os.path.isdir(path):
            logging.info(f"Scanning directory: {path}")
            solidity_files = find_solidity_files_in_directory(path)
            for solidity_file in solidity_files:
                results = scan_solidity_file(solidity_file)
                all_results.append(results)
        elif Web3.isAddress(path):
            logging.info(f"Scanning contract at address: {path}")
            results = scan_solidity_contract_by_address(path)
            if results:
                all_results.append(results)
        else:
            logging.error(f"Error: Invalid path or address - {path}")

    # Output results
    output_format = args.output.split(".")[-1] if args.output else "json"
    formatted_output = output_vulnerabilities(all_results, output_format)

    if args.output:
        try:
            with open(args.output, "w") as file:
                file.write(formatted_output)
            logging.info(f"Results written to {args.output}")
        except Exception as e:
            logging.error(f"Error writing output to file {args.output}: {e}")
    else:
        print(formatted_output)

if __name__ == "__main__":
    main()
