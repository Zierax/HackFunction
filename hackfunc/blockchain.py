import hashlib
import json
import time
from typing import List, Dict, Any, Optional
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import asyncio
import aiohttp
from web3 import Web3
from eth_abi import decode_abi
from eth_utils import function_signature_to_4byte_selector
from solidity_parser import parser
import networkx as nx
from z3 import *
import logging
import os
from dotenv import load_dotenv
from slither import Slither
from slither.analyses.erc.erc20 import ERC20_functions
from slither.core.declarations import Function
from slither.utils.colors import red, green, yellow
from mythril.mythril import MythrilDisassembler
from mythril.ethereum import util
from mythril.analysis.symbolic import SymExecWrapper
from mythril.analysis.report import Report
from manticore.ethereum import ManticoreEVM
from manticore.core.smtlib import ConstraintSet, operators
from echidna import echidna
from pyevmasm import disassemble_hex
from eth_bloom import BloomFilter
from eth_utils import keccak, to_checksum_address
from eth_account import Account
from web3.middleware import geth_poa_middleware
import rlp
from tqdm import tqdm
import concurrent.futures
from scipy import stats
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SmartContractVulnerability:
    def __init__(self, name: str, description: str, severity: str):
        self.name = name
        self.description = description
        self.severity = severity

class BlockchainHacker:
    def __init__(self):
        self.rpc_url = os.getenv('ETHEREUM_RPC_URL')
        if not self.rpc_url:
            raise ValueError("ETHEREUM_RPC_URL not set in environment variables")
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        self.etherscan_api_key = os.getenv('ETHERSCAN_API_KEY')
        if not self.etherscan_api_key:
            logger.warning("ETHERSCAN_API_KEY not set in environment variables. Some features may be limited.")
        self.known_vulnerabilities = {
            "reentrancy": self.check_reentrancy,
            "overflow": self.check_integer_overflow,
            "access_control": self.check_access_control,
            "tx_origin": self.check_tx_origin,
            "dos": self.check_denial_of_service,
            "unchecked_call": self.check_unchecked_call,
            "uninitialized_storage": self.check_uninitialized_storage,
            "arbitrary_jump": self.check_arbitrary_jump,
            "delegatecall": self.check_dangerous_delegatecall,
            "gas_limit_dos": self.check_gas_limit_dos,
            "front_running": self.check_front_running,
            "time_manipulation": self.check_time_manipulation,
            "short_address": self.check_short_address,
            "unchecked_return": self.check_unchecked_return,
            "erc20_compliance": self.check_erc20_compliance,
            "signature_malleability": self.check_signature_malleability,
            "flashloan_vulnerability": self.check_flashloan_vulnerability,
            "oracle_manipulation": self.check_oracle_manipulation,
            "sandwich_attack": self.check_sandwich_attack,
            "governance_attack": self.check_governance_attack,
        }

    async def analyze_smart_contract(self, contract_address: str) -> Dict[str, Any]:
        """Analyze a smart contract for potential vulnerabilities."""
        try:
            contract_code = await self.get_contract_code(contract_address)
            contract_abi = await self.get_contract_abi(contract_address)
            
            results = {}
            tasks = []
            for vuln_name, check_func in self.known_vulnerabilities.items():
                task = asyncio.create_task(check_func(contract_code, contract_abi))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            # Perform advanced analyses
            slither_results = await self.perform_slither_analysis(contract_address)
            mythril_results = await self.perform_mythril_analysis(contract_address)
            manticore_results = await self.perform_manticore_analysis(contract_address)
            echidna_results = await self.perform_echidna_analysis(contract_address)
            
            results['slither_analysis'] = slither_results
            results['mythril_analysis'] = mythril_results
            results['manticore_analysis'] = manticore_results
            results['echidna_analysis'] = echidna_results
            
            return dict(zip(list(self.known_vulnerabilities.keys()) + ['slither_analysis', 'mythril_analysis', 'manticore_analysis', 'echidna_analysis'], results))
        except Exception as e:
            logger.error(f"Error analyzing smart contract: {str(e)}")
            return {"error": str(e)}

    async def get_contract_code(self, contract_address: str) -> str:
        """Fetch the bytecode of a smart contract from the blockchain."""
        try:
            code = await self.w3.eth.get_code(Web3.toChecksumAddress(contract_address))
            return code.hex()
        except Exception as e:
            logger.error(f"Error fetching contract code: {str(e)}")
            return ""

    async def get_contract_abi(self, contract_address: str) -> List[Dict[str, Any]]:
        """Fetch the ABI of a smart contract from Etherscan."""
        if not self.etherscan_api_key:
            logger.warning("Etherscan API key not set. Unable to fetch ABI.")
            return []
        
        url = f"https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={self.etherscan_api_key}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    data = await response.json()
                    if data['status'] == '1':
                        return json.loads(data['result'])
                    else:
                        logger.warning(f"Failed to fetch ABI: {data['message']}")
                        return []
        except Exception as e:
            logger.error(f"Error fetching contract ABI: {str(e)}")
            return []

    async def perform_slither_analysis(self, contract_address: str) -> Dict[str, Any]:
        """Perform static analysis using Slither."""
        try:
            source_code = await self.get_contract_source(contract_address)
            if not source_code:
                return {"error": "Unable to fetch source code"}

            with open("temp_contract.sol", "w") as f:
                f.write(source_code)

            slither = Slither("temp_contract.sol")
            
            results = {
                "vulnerabilities": [],
                "contract_info": {},
                "function_summaries": []
            }

            for contract in slither.contracts:
                results["contract_info"][contract.name] = {
                    "is_upgradeable": contract.is_upgradeable,
                    "is_upgradeable_proxy": contract.is_upgradeable_proxy,
                    "is_erc20": self.is_erc20(contract),
                    "state_variables": [v.name for v in contract.state_variables],
                    "events": [e.full_name for e in contract.events]
                }

                for function in contract.functions:
                    results["function_summaries"].append({
                        "name": function.full_name,
                        "visibility": function.visibility,
                        "modifiers": [m.name for m in function.modifiers],
                        "reads": [v.name for v in function.state_variables_read],
                        "writes": [v.name for v in function.state_variables_written]
                    })

            for detector in slither.detectors:
                results["vulnerabilities"].extend(detector.detect())

            os.remove("temp_contract.sol")

            return results
        except Exception as e:
            logger.error(f"Slither analysis failed: {str(e)}")
            return {"error": str(e)}

    async def perform_mythril_analysis(self, contract_address: str) -> Dict[str, Any]:
        """Perform symbolic execution analysis using Mythril."""
        try:
            contract_code = await self.w3.eth.get_code(Web3.toChecksumAddress(contract_address))
            disassembler = MythrilDisassembler()
            address, _ = disassembler.load_from_bytecode(contract_code)
            sym = SymExecWrapper(disassembler, address)
            issues = sym.fire_lasers()
            return {"issues": [issue.as_dict() for issue in issues]}
        except Exception as e:
            logger.error(f"Mythril analysis failed: {str(e)}")
            return {"error": str(e)}

    async def perform_manticore_analysis(self, contract_address: str) -> Dict[str, Any]:
        """Perform symbolic execution analysis using Manticore."""
        try:
            m = ManticoreEVM()
            contract_account = m.create_account(balance=10**18)
            contract_code = await self.w3.eth.get_code(Web3.toChecksumAddress(contract_address))
            contract = m.create_contract(contract_code, owner=contract_account)
            
            # Symbolic exploration
            m.run(procs=10)
            
            # Collect and return results
            return {"states": m.count_states(), "coverage": m.global_coverage()}
        except Exception as e:
            logger.error(f"Manticore analysis failed: {str(e)}")
            return {"error": str(e)}

    async def perform_echidna_analysis(self, contract_address: str) -> Dict[str, Any]:
        """Perform fuzzing analysis using Echidna."""
        try:
            source_code = await self.get_contract_source(contract_address)
            if not source_code:
                return {"error": "Unable to fetch source code"}

            with open("temp_contract.sol", "w") as f:
                f.write(source_code)

            config = {
                "contractAddr": contract_address,
                "deployer": "0x0000000000000000000000000000000000000000",
                "sender": ["0x0000000000000000000000000000000000000000"],
                "coverage": True,
                "seqLen": 100,
                "testLimit": 50000,
                "shrinkLimit": 5000,
            }

            results = echidna.fuzz("temp_contract.sol", config=config)
            os.remove("temp_contract.sol")
            return results
        except Exception as e:
            logger.error(f"Echidna analysis failed: {str(e)}")
            return {"error": str(e)}

    async def analyze_blockchain(self, start_block: int, end_block: int) -> Dict[str, Any]:
        """Analyze the entire blockchain for potential issues."""
        results = {
            "suspicious_transactions": [],
            "high_gas_usage": [],
            "contract_creations": [],
            "large_value_transfers": [],
            "unusual_patterns": [],
            "potential_flashloans": [],
            "price_manipulation_attempts": [],
            "governance_attacks": [],
            "reentrancy_attacks": [],
            "selfdestruct_calls": [],
            "delegatecall_issues": []
        }

        async def process_block(block_number):
            try:
                block = await self.w3.eth.get_block(block_number, full_transactions=True)
                block_results = {
                    "suspicious_transactions": [],
                    "high_gas_usage": [],
                    "contract_creations": [],
                    "large_value_transfers": [],
                    "unusual_patterns": [],
                    "potential_flashloans": [],
                    "price_manipulation_attempts": [],
                    "governance_attacks": [],
                    "reentrancy_attacks": [],
                    "selfdestruct_calls": [],
                    "delegatecall_issues": []
                }
                
                for tx in block.transactions:
                    # Check for suspicious transactions
                    if await self.is_suspicious_transaction(tx):
                        block_results["suspicious_transactions"].append(tx.hash.hex())
                    
                    # Check for high gas usage
                    if tx.gas > 1000000:  # Arbitrary threshold
                        block_results["high_gas_usage"].append(tx.hash.hex())
                    
                    # Check for contract creations
                    if tx.to is None:
                        block_results["contract_creations"].append(tx.hash.hex())
                    
                    # Check for large value transfers
                    if tx.value > Web3.toWei(100, 'ether'):  # Arbitrary threshold
                        block_results["large_value_transfers"].append(tx.hash.hex())
                    
                    # Check for potential flashloans
                    if await self.is_potential_flashloan(tx):
                        block_results["potential_flashloans"].append(tx.hash.hex())
                    
                    # Check for price manipulation attempts
                    if await self.is_price_manipulation_attempt(tx):
                        block_results["price_manipulation_attempts"].append(tx.hash.hex())
                    
                    # Check for governance attacks
                    if await self.is_governance_attack(tx):
                        block_results["governance_attacks"].append(tx.hash.hex())
                    
                    # Check for reentrancy attacks
                    if await self.is_reentrancy_attack(tx):
                        block_results["reentrancy_attacks"].append(tx.hash.hex())
                    
                    # Check for selfdestruct calls
                    if await self.is_selfdestruct_call(tx):
                        block_results["selfdestruct_calls"].append(tx.hash.hex())
                    
                    # Check for delegatecall issues
                    if await self.is_delegatecall_issue(tx):
                        block_results["delegatecall_issues"].append(tx.hash.hex())
                
                # Check for unusual patterns
                if await self.detect_unusual_patterns(block):
                    block_results["unusual_patterns"].append(block_number)
                
                return block_results
            except Exception as e:
                logger.error(f"Error processing block {block_number}: {str(e)}")
                return {
                    "suspicious_transactions": [],
                    "high_gas_usage": [],
                    "contract_creations": [],
                    "large_value_transfers": [],
                    "unusual_patterns": [],
                    "potential_flashloans": [],
                    "price_manipulation_attempts": [],
                    "governance_attacks": [],
                    "reentrancy_attacks": [],
                    "selfdestruct_calls": [],
                    "delegatecall_issues": []
                }

        # Use ThreadPoolExecutor for parallel processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            loop = asyncio.get_event_loop()
            futures = [
                loop.run_in_executor(executor, process_block, i)
                for i in range(start_block, end_block + 1)
            ]
            for future in tqdm(asyncio.as_completed(futures), total=end_block-start_block+1):
                block_results = await future
                for key in results:
                    results[key].extend(block_results[key])

        return results

    async def is_suspicious_transaction(self, tx) -> bool:
        # Implement logic to detect suspicious transactions
        # This could include checking for known malicious addresses, unusual input data, etc.
        known_malicious_addresses = set()  # Add known malicious addresses here
        if tx['to'] in known_malicious_addresses or tx['from'] in known_malicious_addresses:
            return True
        
        # Check for unusual input data
        if len(tx['input']) > 1000000:  # Arbitrary threshold
            return True
        
        return False

    async def detect_unusual_patterns(self, block) -> bool:
        # Implement logic to detect unusual patterns in a block
        # This could include checking for a sudden spike in transactions, unusual gas prices, etc.
        avg_gas_price = sum(tx['gasPrice'] for tx in block['transactions']) / len(block['transactions'])
        if avg_gas_price > 1000 * 10**9:  # 1000 Gwei
            return True
        
        if len(block['transactions']) > 500:  # Arbitrary threshold
            return True
        
        return False

    async def is_potential_flashloan(self, tx) -> bool:
        # Check if the transaction involves a large amount of tokens being borrowed and repaid in the same transaction
        # This is a simplified check and may need to be more sophisticated in practice
        if tx['value'] > Web3.toWei(1000, 'ether') and tx['from'] == tx['to']:
            return True
        return False

    async def is_price_manipulation_attempt(self, tx) -> bool:
        # Check for transactions that might be attempting to manipulate asset prices
        # This could involve large trades on decentralized exchanges
        known_dex_addresses = set()  # Add known DEX addresses here
        if tx['to'] in known_dex_addresses and tx['value'] > Web3.toWei(100, 'ether'):
            return True
        return False

    async def is_governance_attack(self, tx) -> bool:
        # Check for potential governance attacks, such as flash loan attacks on governance tokens
        known_governance_contracts = set()  # Add known governance contract addresses here
        if tx['to'] in known_governance_contracts and tx['value'] > Web3.toWei(10000, 'ether'):
            return True
        return False

    async def is_reentrancy_attack(self, tx) -> bool:
        # Check for potential reentrancy attacks
        # This is a simplified check and would need to be more sophisticated in practice
        if 'call' in tx['input'] and 'delegatecall' in tx['input']:
            return True
        return False

    async def is_selfdestruct_call(self, tx) -> bool:
        # Check for selfdestruct calls
        if 'selfdestruct' in tx['input']:
            return True
        return False

    async def is_delegatecall_issue(self, tx) -> bool:
        # Check for delegatecall issues
        if 'delegatecall' in tx['input']:
            return True
        return False

    async def audit_contract(self, contract_address: str) -> Dict[str, Any]:
        """Perform a comprehensive audit of a smart contract."""
        try:
            vulnerabilities = await self.analyze_smart_contract(contract_address)
            transaction_history = await self.analyze_transaction_history(contract_address)
            fuzz_results = await self.fuzz_contract(contract_address)
            blockchain_analysis = await self.analyze_blockchain(self.w3.eth.block_number - 1000, self.w3.eth.block_number)
            
            return {
                "vulnerabilities": vulnerabilities,
                "transaction_history": transaction_history,
                "fuzz_results": fuzz_results,
                "blockchain_analysis": blockchain_analysis
            }
        except Exception as e:
            logger.error(f"Error auditing contract: {str(e)}")
            return {"error": str(e)}

    async def analyze_transaction_history(self, contract_address: str) -> Dict[str, Any]:
        """Analyze the transaction history of a contract."""
        try:
            transactions = await self.get_contract_transactions(contract_address)
            
            # Perform statistical analysis on transaction data
            values = [tx['value'] for tx in transactions]
            gas_prices = [tx['gasPrice'] for tx in transactions]
            
            return {
                "total_transactions": len(transactions),
                "total_value": sum(values),
                "avg_value": statistics.mean(values),
                "median_value": statistics.median(values),
                "avg_gas_price": statistics.mean(gas_prices),
                "unusual_transactions": self.detect_unusual_transactions(transactions)
            }
        except Exception as e:
            logger.error(f"Error analyzing transaction history: {str(e)}")
            return {"error": str(e)}

    def detect_unusual_transactions(self, transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual transactions using statistical methods."""
        values = [tx['value'] for tx in transactions]
        gas_prices = [tx['gasPrice'] for tx in transactions]
        
        # Use Z-score to detect outliers
        value_z_scores = stats.zscore(values)
        gas_price_z_scores = stats.zscore(gas_prices)
        
        unusual_transactions = []
        for i, (value_z, gas_z) in enumerate(zip(value_z_scores, gas_price_z_scores)):
            if abs(value_z) > 3 or abs(gas_z) > 3:  # Z-score > 3 is considered unusual
                unusual_transactions.append(transactions[i])
        
        return unusual_transactions

    async def fuzz_contract(self, contract_address: str) -> Dict[str, Any]:
        """Perform fuzz testing on a smart contract."""
        try:
            abi = await self.get_contract_abi(contract_address)
            
            results = {}
            for func in abi:
                if func['type'] == 'function':
                    results[func['name']] = await self.fuzz_function(contract_address, func)
            
            return results
        except Exception as e:
            logger.error(f"Error fuzzing contract: {str(e)}")
            return {"error": str(e)}

    async def fuzz_function(self, contract_address: str, func: Dict[str, Any]) -> Dict[str, Any]:
        """Fuzz a single function of a smart contract."""
        # Generate random inputs for the function
        inputs = self.generate_random_inputs(func['inputs'])
        
        # Call the function with the generated inputs
        try:
            result = await self.call_contract_function(contract_address, func['name'], inputs)
            return {"status": "success", "result": result}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def generate_random_inputs(self, input_types: List[Dict[str, str]]) -> List[Any]:
        """Generate random inputs for a function based on its input types."""
        inputs = []
        for input_type in input_types:
            if input_type['type'] == 'uint256':
                inputs.append(random.randint(0, 2**256 - 1))
            elif input_type['type'] == 'address':
                inputs.append(Web3.toChecksumAddress(os.urandom(20).hex()))
            elif input_type['type'] == 'bool':
                inputs.append(random.choice([True, False]))
            elif input_type['type'].startswith('bytes'):
                size = int(input_type['type'][5:]) if len(input_type['type']) > 5 else 32
                inputs.append(os.urandom(size))
            else:
                inputs.append(None)  # Placeholder for unsupported types
        return inputs

    async def call_contract_function(self, contract_address: str, function_name: str, inputs: List[Any]) -> Any:
        """Call a contract function with the given inputs."""
        try:
            contract = self.w3.eth.contract(address=contract_address, abi=await self.get_contract_abi(contract_address))
            function = getattr(contract.functions, function_name)
            return await function(*inputs).call()
        except Exception as e:
            logger.error(f"Error calling contract function {function_name}: {str(e)}")
            return None

    async def check_flashloan_vulnerability(self, contract_code: str, contract_abi: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check for potential flash loan vulnerabilities."""
        try:
            # This is a simplified check and would need to be more sophisticated in practice
            vulnerable_functions = []
            for func in contract_abi:
                if func['type'] == 'function' and any(param['type'] == 'uint256' for param in func.get('inputs', [])):
                    if 'onFlashLoan' in func['name'] or 'flashLoan' in func['name']:
                        vulnerable_functions.append(func['name'])
            
            return {
                "vulnerable": len(vulnerable_functions) > 0,
                "vulnerable_functions": vulnerable_functions
            }
        except Exception as e:
            logger.error(f"Error checking flashloan vulnerability: {str(e)}")
            return {"error": str(e)}

    async def check_oracle_manipulation(self, contract_code: str, contract_abi: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check for potential oracle manipulation vulnerabilities."""
        try:
            # This is a simplified check and would need to be more sophisticated in practice
            vulnerable_functions = []
            for func in contract_abi:
                if func['type'] == 'function' and any(param['type'] == 'address' for param in func.get('inputs', [])):
                    if 'oracle' in func['name'].lower() or 'price' in func['name'].lower():
                        vulnerable_functions.append(func['name'])
            
            return {
                "vulnerable": len(vulnerable_functions) > 0,
                "vulnerable_functions": vulnerable_functions
            }
        except Exception as e:
            logger.error(f"Error checking oracle manipulation: {str(e)}")
            return {"error": str(e)}

    async def check_sandwich_attack(self, contract_code: str, contract_abi: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check for potential sandwich attack vulnerabilities."""
        try:
            # This is a simplified check and would need to be more sophisticated in practice
            vulnerable_functions = []
            for func in contract_abi:
                if func['type'] == 'function' and 'swap' in func['name'].lower():
                    vulnerable_functions.append(func['name'])
            
            return {
                "vulnerable": len(vulnerable_functions) > 0,
                "vulnerable_functions": vulnerable_functions
            }
        except Exception as e:
            logger.error(f"Error checking sandwich attack: {str(e)}")
            return {"error": str(e)}

    async def check_governance_attack(self, contract_code: str, contract_abi: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check for potential governance attack vulnerabilities."""
        try:
            # This is a simplified check and would need to be more sophisticated in practice
            vulnerable_functions = []
            for func in contract_abi:
                if func['type'] == 'function' and ('vote' in func['name'].lower() or 'propose' in func['name'].lower()):
                    vulnerable_functions.append(func['name'])
            
            return {
                "vulnerable": len(vulnerable_functions) > 0,
                "vulnerable_functions": vulnerable_functions
            }
        except Exception as e:
            logger.error(f"Error checking governance attack: {str(e)}")
            return {"error": str(e)}

    async def analyze_token_transfers(self, contract_address: str, start_block: int, end_block: int) -> Dict[str, Any]:
        """Analyze token transfers for potential anomalies."""
        try:
            transfers = await self.get_token_transfers(contract_address, start_block, end_block)
            
            # Perform clustering analysis on transfer amounts
            amounts = [transfer['value'] for transfer in transfers]
            X = np.array(amounts).reshape(-1, 1)
            X = StandardScaler().fit_transform(X)
            
            db = DBSCAN(eps=0.3, min_samples=10).fit(X)
            labels = db.labels_
            
            # Number of clusters in labels, ignoring noise if present
            n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
            
            return {
                "total_transfers": len(transfers),
                "unique_senders": len(set(transfer['from'] for transfer in transfers)),
                "unique_recipients": len(set(transfer['to'] for transfer in transfers)),
                "number_of_clusters": n_clusters_,
                "potential_anomalies": [transfers[i] for i, label in enumerate(labels) if label == -1]
            }
        except Exception as e:
            logger.error(f"Error analyzing token transfers: {str(e)}")
            return {"error": str(e)}

    async def get_token_transfers(self, contract_address: str, start_block: int, end_block: int) -> List[Dict[str, Any]]:
        """Fetch token transfer events for a given contract."""
        try:
            contract = self.w3.eth.contract(address=contract_address, abi=await self.get_contract_abi(contract_address))
            transfer_filter = contract.events.Transfer.createFilter(fromBlock=start_block, toBlock=end_block)
            return [event['args'] for event in transfer_filter.get_all_entries()]
        except Exception as e:
            logger.error(f"Error fetching token transfers: {str(e)}")
            return []

 