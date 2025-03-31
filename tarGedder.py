#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive Network and Web Reconnaissance Framework
A modular, object-oriented framework for security reconnaissance
"""
import enum
import os
import re
import sys
import json
import yaml
import time
import socket
import random
import logging
import asyncio
import ipaddress
import subprocess
import urllib.parse
import argparse
from abc import ABC, abstractmethod
from typing import List, Dict, Set, Tuple, Optional, Union, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from contextlib import asynccontextmanager

import aiohttp
import aiofiles
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, r2_score
from bs4 import BeautifulSoup
from io import BytesIO
import base64
import esprima  # For JavaScript parsing

from smb.SMBConnection import SMBConnection


colors = {
    'Critical': 'darkred',
    'High': 'red',
    'Medium': 'orange',
    'Low': 'yellow',
    'Info': 'blue'
}
###########################################
# Core Classes: Configuration & Settings  #
###########################################

class ConfigManager:
    """Manager for configuration settings"""

    def __init__(self, config_file: str = "config.yaml"):
        self.__config_file = config_file
        self.__config_data = {}
        self.__logger = logging.getLogger(self.__class__.__name__)

    @property
    def config_file(self) -> str:
        """Get the configuration file path"""
        return self.__config_file

    async def load(self) -> Dict:
        """Load configuration from file"""
        try:
            async with aiofiles.open(self.__config_file, "r") as f:
                content = await f.read()
                self.__config_data = yaml.safe_load(content)
                return self.__config_data
        except Exception as e:
            self.__logger.error(f"Failed to load config from {self.__config_file}: {e}")
            self.__config_data = {}
            return self.__config_data

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        return self.__config_data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value"""
        self.__config_data[key] = value

    async def save(self) -> bool:
        """Save configuration to file"""
        try:
            async with aiofiles.open(self.__config_file, "w") as f:
                await f.write(yaml.dump(self.__config_data, default_flow_style=False))
            return True
        except Exception as e:
            self.__logger.error(f"Failed to save config to {self.__config_file}: {e}")
            return False


class ScannerConfig:
    """Configuration for scanners"""

    def __init__(self, config_data: Dict = None):
        self.__config_data = config_data or {}

    @classmethod
    async def from_yaml(cls, file_path: str):
        """Load configuration from YAML file"""
        config_manager = ConfigManager(file_path)
        config_data = await config_manager.load()
        return cls(config_data)

    @property
    def scan_timeout(self) -> int:
        """Get scan timeout value"""
        return self.__config_data.get("scan_timeout", 60)

    @property
    def tools(self) -> List[str]:
        """Get required tools list"""
        return self.__config_data.get("tools", [])

    @property
    def network_interface(self) -> str:
        """Get network interface to use"""
        return self.__config_data.get("network_interface", "eth0")

    @property
    def install_commands(self) -> Dict[str, str]:
        """Get tool installation commands"""
        return self.__config_data.get("tools_install_commands", {})

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        return self.__config_data.get(key, default)


class LoggingManager:
    """Manager for logging operations"""

    def __init__(self, log_file: str = "recon.log", log_level: int = logging.INFO):
        self.__log_file = log_file
        self.__log_level = log_level
        self.__setup_logging()

    def __setup_logging(self) -> None:
        """Set up logging configuration"""
        logging.basicConfig(
            level=self.__log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(self.__log_file),
                logging.StreamHandler()
            ]
        )

    @property
    def logger(self) -> logging.Logger:
        """Get a logger instance"""
        return logging.getLogger()

    def get_logger(self, name: str) -> logging.Logger:
        """Get a named logger instance"""
        return logging.getLogger(name)


###########################################
# Security Models: Credential & Auth      #
###########################################

class Credential:
    """Credential model for authentication"""

    def __init__(self, username: str = "", password: str = ""):
        self.__username = username
        self.__password = password

    @property
    def username(self) -> str:
        """Get the username"""
        return self.__username

    @property
    def password(self) -> str:
        """Get the password"""
        return self.__password

    def as_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "username": self.__username,
            "password": self.__password
        }

    def __str__(self) -> str:
        """String representation"""
        return f"{self.__username}:{'*' * len(self.__password)}"


class CredentialManager:
    """Manager for multiple credentials"""

    def __init__(self, default_credential: Optional[Credential] = None, cred_file: Optional[str] = None):
        self.__credentials = []
        self.__logger = logging.getLogger(self.__class__.__name__)

        if default_credential and (default_credential.username or default_credential.password):
            self.__credentials.append(default_credential)

        if cred_file:
            self.__load_credentials_from_file(cred_file)

        # Add default/anonymous credentials if none specified
        if not self.__credentials:
            self.__credentials.append(Credential("", ""))
            self.__credentials.append(Credential("guest", ""))

    def __load_credentials_from_file(self, cred_file: str) -> None:
        """Load credentials from a file"""
        try:
            with open(cred_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        username, password = line.strip().split(':', 1)
                        self.__credentials.append(Credential(username, password))
        except Exception as e:
            self.__logger.error(f"Failed to load credentials from {cred_file}: {e}")

    @property
    def credentials(self) -> List[Credential]:
        """Get all credentials"""
        return self.__credentials

    def add_credential(self, credential: Credential) -> None:
        """Add a credential"""
        self.__credentials.append(credential)


###########################################
# Command Execution                       #
###########################################

class CommandExecutor:
    """Executes shell commands asynchronously"""

    def __init__(self, timeout: int = 60):
        self.__timeout = timeout
        self.__logger = logging.getLogger(self.__class__.__name__)

    async def execute(self, command: List[str], output_file: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Execute a command and optionally save output to file"""
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.__timeout)
                stdout_text = stdout.decode() if stdout else None

                if output_file and stdout_text:
                    async with aiofiles.open(output_file, "w") as f:
                        await f.write(stdout_text)

                success = proc.returncode == 0
                return success, stdout_text

            except asyncio.TimeoutError:
                proc.terminate()
                self.__logger.error(f"Command timed out: {' '.join(command)}")
                return False, None

        except Exception as e:
            self.__logger.error(f"Command execution failed: {str(e)}")
            return False, None


###########################################
# Environment Validation                  #
###########################################

class EnvironmentValidator:
    """Validates and sets up the operating environment"""

    def __init__(self, config: ScannerConfig):
        self.__config = config
        self.__logger = logging.getLogger(self.__class__.__name__)
        self.__executor = CommandExecutor(timeout=30)

    async def is_tool_installed(self, tool: str) -> bool:
        """Check if a tool is installed"""
        success, _ = await self.__executor.execute(["which", tool])
        return success

    async def install_tool(self, tool: str) -> bool:
        """Attempt to install a missing tool"""
        install_commands = self.__config.install_commands
        if tool not in install_commands:
            self.__logger.error(f"No installation recipe for {tool}")
            return False

        install_cmd = install_commands[tool]
        self.__logger.info(f"Installing {tool} using command: {install_cmd}")

        success, _ = await self.__executor.execute(["bash", "-c", install_cmd])
        if not success:
            self.__logger.error(f"Failed to install {tool}")
            return False

        return await self.is_tool_installed(tool)

    async def validate(self) -> bool:
        """Validate the environment"""
        missing_tools = []

        for tool in self.__config.tools:
            if not await self.is_tool_installed(tool):
                self.__logger.warning(f"{tool} not found. Attempting to install...")
                if not await self.install_tool(tool):
                    missing_tools.append(tool)

        if missing_tools:
            self.__logger.error(f"Missing required tools: {', '.join(missing_tools)}")
            return False

        return True


###########################################
# Result Models                           #
###########################################

class ScanResult:
    """Base class for scan results"""

    def __init__(self, target: str, scanner_name: str, success: bool = True, message: str = None, output_file: str = None):
        self.__target = target
        self.__scanner_name = scanner_name
        self.__success = success
        self.__message = message
        self.__output_file = output_file
        self.__timestamp = datetime.now().isoformat()

    @property
    def target(self) -> str:
        """Get the target"""
        return self.__target

    @property
    def scanner_name(self) -> str:
        """Get the scanner name"""
        return self.__scanner_name

    @property
    def success(self) -> bool:
        """Get the success status"""
        return self.__success

    @property
    def message(self) -> str:
        """Get the message"""
        return self.__message

    @property
    def output_file(self) -> str:
        """Get the output file"""
        return self.__output_file

    @property
    def timestamp(self) -> str:
        """Get the timestamp"""
        return self.__timestamp

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "target": self.__target,
            "scanner": self.__scanner_name,
            "success": self.__success,
            "message": self.__message,
            "output_file": self.__output_file,
            "timestamp": self.__timestamp
        }


class CommandScanResult(ScanResult):
    """Result from a command-based scan"""

    def __init__(self, target: str, scanner_name: str, command: List[str],
                 output: str = None, output_file: str = None, **kwargs):
        super().__init__(target, scanner_name, **kwargs)
        self.__command = command
        self.__output = output

    @property
    def command(self) -> List[str]:
        """Get the command"""
        return self.__command

    @property
    def output(self) -> str:
        """Get the command output"""
        return self.__output

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        result = super().to_dict()
        result.update({
            "command": " ".join(self.__command),
            "output": self.__output[:1000] + "..." if self.__output and len(self.__output) > 1000 else self.__output
        })
        return result


class ShareInfo:
    """Information about an SMB share"""

    def __init__(self, name: str, comment: str = "", share_type: str = None):
        self.__name = name
        self.__comment = comment
        self.__type = share_type
        self.__files = []
        self.__access_error = None

    @property
    def name(self) -> str:
        """Get share name"""
        return self.__name

    @property
    def comment(self) -> str:
        """Get share comment"""
        return self.__comment

    @property
    def type(self) -> str:
        """Get share type"""
        return self.__type

    @property
    def files(self) -> List[str]:
        """Get files in share"""
        return self.__files

    @files.setter
    def files(self, value: List[str]) -> None:
        """Set files in share"""
        self.__files = value

    @property
    def access_error(self) -> str:
        """Get access error"""
        return self.__access_error

    @access_error.setter
    def access_error(self, value: str) -> None:
        """Set access error"""
        self.__access_error = value

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "name": self.__name,
            "comment": self.__comment,
            "type": self.__type,
            "files": self.__files[:10] if self.__files else [],  # Limit to first 10 files
            "access_error": self.__access_error
        }


class SMBInfo:
    """Information about SMB server"""

    def __init__(self):
        self.__os_info = {}
        self.__protocols = []
        self.__dialect = None
        self.__shares = []
        self.__users = set()
        self.__groups = set()
        self.__vulnerabilities = []

    @property
    def os_info(self) -> Dict[str, str]:
        """Get OS info"""
        return self.__os_info

    @property
    def protocols(self) -> List[str]:
        """Get protocols"""
        return self.__protocols

    @property
    def dialect(self) -> str:
        """Get dialect"""
        return self.__dialect

    @dialect.setter
    def dialect(self, value: str) -> None:
        """Set dialect"""
        self.__dialect = value

    @property
    def shares(self) -> List[ShareInfo]:
        """Get shares"""
        return self.__shares

    @property
    def users(self) -> Set[str]:
        """Get users"""
        return self.__users

    @property
    def groups(self) -> Set[str]:
        """Get groups"""
        return self.__groups

    @property
    def vulnerabilities(self) -> List[str]:
        """Get vulnerabilities"""
        return self.__vulnerabilities

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "os_info": self.__os_info,
            "protocols": self.__protocols,
            "dialect": self.__dialect,
            "shares": [share.to_dict() for share in self.__shares],
            "users": list(self.__users),
            "groups": list(self.__groups),
            "vulnerabilities": self.__vulnerabilities
        }

    def add_share(self, share: ShareInfo) -> None:
        """Add a share"""
        self.__shares.append(share)

    def add_user(self, user: str) -> None:
        """Add a user"""
        self.__users.add(user)

    def add_group(self, group: str) -> None:
        """Add a group"""
        self.__groups.add(group)

    def add_vulnerability(self, vulnerability: str) -> None:
        """Add a vulnerability"""
        self.__vulnerabilities.append(vulnerability)

    def update_os_info(self, info: Dict[str, str]) -> None:
        """Update OS info"""
        self.__os_info.update(info)

    def add_protocol(self, protocol: str) -> None:
        """Add a protocol"""
        self.__protocols.append(protocol)


class WebVulnerability:
    """Web vulnerability information"""

    def __init__(self, name: str, description: str, severity: str = "medium", url: str = None):
        self.__name = name
        self.__description = description
        self.__severity = severity
        self.__url = url
        self.__timestamp = datetime.now().isoformat()

    @property
    def name(self) -> str:
        """Get name"""
        return self.__name

    @property
    def description(self) -> str:
        """Get description"""
        return self.__description

    @property
    def severity(self) -> str:
        """Get severity"""
        return self.__severity

    @property
    def url(self) -> str:
        """Get URL"""
        return self.__url

    @property
    def timestamp(self) -> str:
        """Get timestamp"""
        return self.__timestamp

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "name": self.__name,
            "description": self.__description,
            "severity": self.__severity,
            "url": self.__url,
            "timestamp": self.__timestamp
        }


class ScriptInfo:
    """Information about a JavaScript file"""

    def __init__(self, url: str, content: str = None):
        self.__url = url
        self.__content = content
        self.__size = len(content) if content else 0
        self.__imports = []
        self.__exports = []
        self.__api_endpoints = []
        self.__dom_interactions = []
        self.__storage_usage = False
        self.__cookie_usage = False
        self.__sensitive_functions = []
        self.__frameworks = []
        self.__minified = False
        self.__obfuscated = False

    @property
    def url(self) -> str:
        """Get URL"""
        return self.__url

    @property
    def content(self) -> str:
        """Get content"""
        return self.__content

    @property
    def size(self) -> int:
        """Get size"""
        return self.__size

    @property
    def imports(self) -> List[str]:
        """Get imports"""
        return self.__imports

    @property
    def exports(self) -> List[str]:
        """Get exports"""
        return self.__exports

    @property
    def api_endpoints(self) -> List[str]:
        """Get API endpoints"""
        print("\n[+] API Endpoints:", self.__api_endpoints)
        return self.__api_endpoints

    @property
    def dom_interactions(self) -> List[str]:
        """Get DOM interactions"""
        print("\n[+] DOM Interactions:", self.__dom_interactions)
        return self.__dom_interactions

    @property
    def storage_usage(self) -> bool:
        """Get storage usage flag"""
        if self.__storage_usage:
            print("[-] Storage Usage: ", self.__storage_usage)
        else:
            print("[+] Storage Usage: ", self.__storage_usage)
        return self.__storage_usage

    @property
    def cookie_usage(self) -> bool:
        """Get cookie usage flag"""
        if self.__cookie_usage:
            print("[-] Cookie Usage: ", self.__cookie_usage)
        else:
            print("[+] Cookie Usage: ", self.__cookie_usage)
        return self.__cookie_usage

    @property
    def sensitive_functions(self) -> List[str]:
        """Get sensitive functions"""
        return self.__sensitive_functions

    @property
    def frameworks(self) -> List[str]:
        """Get frameworks"""
        return self.__frameworks

    @property
    def minified(self) -> bool:
        """Get minified flag"""
        return self.__minified

    @property
    def obfuscated(self) -> bool:
        """Get obfuscated flag"""
        return self.__obfuscated

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "url": self.__url,
            "size": self.__size,
            "imports": self.__imports,
            "exports": self.__exports,
            "api_endpoints": self.__api_endpoints,
            "dom_interactions": self.__dom_interactions,
            "storage_usage": self.__storage_usage,
            "cookie_usage": self.__cookie_usage,
            "sensitive_functions": self.__sensitive_functions,
            "frameworks": self.__frameworks,
            "minified": self.__minified,
            "obfuscated": self.__obfuscated
        }

    def add_import(self, imp: str) -> None:
        """Add an import"""
        if imp not in self.__imports:
            self.__imports.append(imp)

    def add_export(self, exp: str) -> None:
        """Add an export"""
        if exp not in self.__exports:
            self.__exports.append(exp)

    def add_api_endpoint(self, endpoint: str) -> None:
        """Add an API endpoint"""
        if endpoint not in self.__api_endpoints:
            self.__api_endpoints.append(endpoint)

    def add_dom_interaction(self, interaction: str) -> None:
        """Add a DOM interaction"""
        if interaction not in self.__dom_interactions:
            self.__dom_interactions.append(interaction)

    def add_sensitive_function(self, function: str) -> None:
        """Add a sensitive function"""
        if function not in self.__sensitive_functions:
            self.__sensitive_functions.append(function)

    def add_framework(self, framework: str) -> None:
        """Add a framework"""
        if framework not in self.__frameworks:
            self.__frameworks.append(framework)

    def set_minified(self, minified: bool) -> None:
        """Set minified flag"""
        self.__minified = minified

    def set_obfuscated(self, obfuscated: bool) -> None:
        """Set obfuscated flag"""
        self.__obfuscated = obfuscated

    def set_storage_usage(self, usage: bool) -> None:
        """Set storage usage flag"""
        self.__storage_usage = usage

    def set_cookie_usage(self, usage: bool) -> None:
        """Set cookie usage flag"""
        self.__cookie_usage = usage


class AggregatedResult:
    """Aggregated results from multiple scanners"""

    def __init__(self, target: str):
        self.target = target
        self.scan_results = {}
        self.__smb_info = SMBInfo()
        self.__web_info = {
            "api_endpoints": [],
            "scripts": [],
            "vulnerabilities": []
        }
        self.__timestamp = datetime.now().isoformat()

    @property
    def target(self) -> str:
        """Get target"""
        return self.__target

    @property
    def scan_results(self) -> Dict[str, ScanResult]:
        """Get scan results"""
        return self.__scan_results

    @property
    def smb_info(self) -> SMBInfo:
        """Get SMB info"""
        return self.__smb_info

    @property
    def web_info(self) -> Dict:
        """Get web info"""
        return self.__web_info

    @property
    def timestamp(self) -> str:
        """Get timestamp"""
        return self.__timestamp

    def add_result(self, result: ScanResult) -> None:
        """Add a scan result"""
        self.__scan_results[result.scanner_name] = result

    def add_api_endpoint(self, endpoint: str) -> None:
        """Add an API endpoint"""
        if endpoint not in self.__web_info["api_endpoints"]:
            self.__web_info["api_endpoints"].append(endpoint)

    def add_script(self, script: ScriptInfo) -> None:
        """Add a script"""
        self.__web_info["scripts"].append(script)

    def add_web_vulnerability(self, vulnerability: WebVulnerability) -> None:
        """Add a web vulnerability"""
        self.__web_info["vulnerabilities"].append(vulnerability)

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "target": self.__target,
            "timestamp": self.__timestamp,
            "scan_results": {name: result.to_dict() for name, result in self.__scan_results.items()},
            "smb_info": self.__smb_info.to_dict(),
            "web_info": {
                "api_endpoints": self.__web_info["api_endpoints"],
                "scripts": [script.to_dict() for script in self.__web_info["scripts"]],
                "vulnerabilities": [vuln.to_dict() for vuln in self.__web_info["vulnerabilities"]]
            }
        }

    async def save_to_file(self, file_path: str) -> None:
        """Save results to file"""
        try:
            async with aiofiles.open(file_path, "w") as f:
                await f.write(json.dumps(self.to_dict(), indent=2))
        except Exception as e:
            logging.error(f"Error saving results to {file_path}: {e}")


###########################################
# Base Scanner Abstract Class             #
###########################################

class BaseScanner(ABC):
    """Abstract base class for all scanners"""

    def __init__(self, target: str, config: ScannerConfig,
                 credential: Optional[Credential] = None,
                 results_dir: str = "recon_results"):
        self._target = target
        self._config = config
        self._credential = credential
        self._results_dir = results_dir
        self._logger = logging.getLogger(self.__class__.__name__)
        self._executor = CommandExecutor(timeout=config.scan_timeout)

        # Create results directory
        os.makedirs(results_dir, exist_ok=True)

    @property
    def target(self) -> str:
        """Get target"""
        return self._target

    @property
    def config(self) -> ScannerConfig:
        """Get config"""
        return self._config

    @property
    def credential(self) -> Optional[Credential]:
        """Get credential"""
        return self._credential

    @property
    def results_dir(self) -> str:
        """Get results directory"""
        return self._results_dir

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner name"""
        pass

    @abstractmethod
    async def scan(self) -> ScanResult:
        """Perform the scan"""
        pass

    def get_output_file(self, suffix: str = "") -> str:
        """Get output file path"""
        filename = f"{self.name}{suffix}_{self.target}.txt"
        return os.path.join(self.results_dir, filename)


###########################################
# Network Scanner Classes                 #
###########################################

class NetworkScanner(BaseScanner):
    """Base class for network scanners"""

    async def is_host_alive(self) -> bool:
        """Check if host is alive using ping"""
        # Different ping command parameters for different operating systems
        if sys.platform.lower() == "win32":
            cmd = ["ping", "-n", "3", "-w", "1000", self.target]
        else:
            cmd = ["ping", "-c", "3", "-W", "1", self.target]

        success, output = await self._executor.execute(cmd)

        if success and output:
            if "ttl=" in output.lower() or "time=" in output.lower():
                return True

        return False


class PingScanner(NetworkScanner):
    """Scanner for ping tests"""

    @property
    def name(self) -> str:
        return "ping"

    async def scan(self) -> CommandScanResult:
        """Perform a ping scan"""
        # Build the command based on OS
        if sys.platform.lower() == "win32":
            cmd = ["ping", "-n", "4", self.target]
        else:
            cmd = ["ping", "-c", "4", self.target]

        output_file = self.get_output_file()
        success, output = await self._executor.execute(cmd, output_file)

        # Parse and display results
        if success and output:
            # Extract packet loss and round-trip times if available
            packet_loss = "Unknown"
            avg_time = "Unknown"

            if "packet loss" in output:
                packet_loss_match = re.search(r'(\d+)% packet loss', output)
                if packet_loss_match:
                    packet_loss = f"{packet_loss_match.group(1)}%"

            if "avg" in output:
                avg_match = re.search(r'= [^/]*/([^/]*)/[^/]*/[^/]*\s', output)
                if avg_match:
                    avg_time = f"{avg_match.group(1)} ms"

            # Print results to console
            print("\nPing Results:")
            print("-" * 50)
            print(f"Target: {self.target}")
            print(f"Status: {'Alive' if 'bytes from' in output or 'Reply from' in output else 'Not responding'}")
            print(f"Packet Loss: {packet_loss}")
            print(f"Average Round-trip Time: {avg_time}")
            print("-" * 50 + "\n")

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Ping scan completed successfully" if success else "Ping scan failed"
        )


class TracerouteScanner(NetworkScanner):
    """Scanner for traceroute with DNS lookups"""

    @property
    def name(self) -> str:
        return "traceroute"

    async def scan(self) -> CommandScanResult:
        """Perform a traceroute with DNS lookups"""
        # Determine the command based on OS
        cmd = []
        if sys.platform.lower() == "win32":
            cmd = ["tracert", self.target]
        else:
            cmd = ["traceroute", "-n", self.target]

        output_file = self.get_output_file()
        success, output = await self._executor.execute(cmd, output_file)

        # Perform DNS lookups for each hop
        if success and output:
            enhanced_output = await self._enhance_with_dns_lookups(output)

            # Write enhanced output to file
            async with aiofiles.open(output_file, "w") as f:
                await f.write(enhanced_output)

            # Print summary
            print("\nTraceroute Results:")
            print("-" * 50)
            print(f"Path to {self.target} completed with {enhanced_output.count('Hop #')} hops")
            print(f"Full details saved to: {output_file}")
            print("-" * 50 + "\n")

            # Update output for the result
            output = enhanced_output

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Traceroute completed successfully" if success else "Traceroute failed"
        )

    async def _enhance_with_dns_lookups(self, traceroute_output: str) -> str:
        """Enhance traceroute output with DNS lookups"""
        enhanced_output = "Traceroute with DNS Lookups\n"
        enhanced_output += "=" * 50 + "\n\n"

        # Extract IP addresses from traceroute output
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        hop_number = 0
        for line in traceroute_output.splitlines():
            hop_number += 1

            # Skip lines without IP addresses
            ips = re.findall(ip_pattern, line)
            if not ips:
                enhanced_output += f"Hop #{hop_number}: No response\n"
                continue

            # Get the first IP in the line
            ip = ips[0]

            # Perform DNS lookup
            try:
                cmd = ["dig", "+short", "-x", ip]
                success, dig_output = await self._executor.execute(cmd)

                hostname = "No DNS record"
                if success and dig_output and dig_output.strip():
                    hostname = dig_output.strip().rstrip('.')

                enhanced_output += f"Hop #{hop_number}: {ip} ({hostname})\n"

            except Exception as e:
                enhanced_output += f"Hop #{hop_number}: {ip} (DNS lookup failed: {str(e)})\n"

        return enhanced_output


class DNSLookupScanner(NetworkScanner):
    """Scanner for comprehensive DNS lookups"""

    @property
    def name(self) -> str:
        return "dns_lookup"

    async def scan(self) -> CommandScanResult:
        """Perform comprehensive DNS lookups"""
        # Skip if target is an IP address without reverse DNS
        if self._is_ip_address(self.target):
            self._logger.info(f"{self.target} is an IP address, performing reverse DNS lookup")
            return await self._perform_reverse_lookup()

        # For domains, perform forward lookups for various record types
        output_file = self.get_output_file()

        record_types = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME"]

        combined_output = f"DNS Lookup Results for {self.target}\n"
        combined_output += "=" * 50 + "\n\n"

        print("\nDNS Lookup Results:")
        print("-" * 50)
        print(f"Target: {self.target}")

        for record_type in record_types:
            cmd = ["dig", "+short", self.target, record_type]
            success, output = await self._executor.execute(cmd)

            if success:
                result = output.strip() if output and output.strip() else "No records found"
                combined_output += f"{record_type} Records:\n{result}\n\n"

                # Print summarized output to console
                record_count = 0 if not output or not output.strip() else len(output.strip().splitlines())
                print(f"{record_type} Records: {record_count} found")

        # Write combined output to file
        async with aiofiles.open(output_file, "w") as f:
            await f.write(combined_output)

        print("-" * 50)
        print(f"Full DNS details saved to: {output_file}")
        print("-" * 50 + "\n")

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=["dig", "multiple", "records"],
            output=combined_output,
            output_file=output_file,
            success=True,
            message=f"DNS lookup completed for {self.target}"
        )

    async def _perform_reverse_lookup(self) -> CommandScanResult:
        """Perform a reverse DNS lookup for an IP address"""
        output_file = self.get_output_file("_reverse")
        cmd = ["dig", "+short", "-x", self.target]

        success, output = await self._executor.execute(cmd, output_file)

        hostname = "No reverse DNS record found"
        if success and output and output.strip():
            hostname = output.strip().rstrip('.')

        # Print results
        print("\nReverse DNS Lookup:")
        print("-" * 50)
        print(f"IP Address: {self.target}")
        print(f"Hostname: {hostname}")
        print("-" * 50 + "\n")

        return CommandScanResult(
            target=self.target,
            scanner_name=f"{self.name}_reverse",
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message=f"Reverse DNS lookup completed for {self.target}"
        )

    def _is_ip_address(self, target: str) -> bool:
        """Check if the target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False


class SSHScanner(NetworkScanner):
    """Scanner for SSH service detection"""

    @property
    def name(self) -> str:
        return "ssh"

    async def scan(self) -> CommandScanResult:
        """Perform an SSH handshake attempt"""
        # Try SSH handshake
        output_file = self.get_output_file()
        is_open, version = await self._try_ssh_handshake()

        # Format output
        output = f"SSH Scan Results for {self.target}:\n"
        output += f"SSH Service: {'Available' if is_open else 'Not available'}\n"
        output += f"SSH Version: {version}\n"

        # Write to file
        async with aiofiles.open(output_file, "w") as f:
            await f.write(output)

        # Print results
        print("\nSSH Scan Results:")
        print("-" * 50)
        print(f"Target: {self.target}")
        print(f"SSH Service: {'Available' if is_open else 'Not available'}")
        print(f"SSH Version: {version}")
        print("-" * 50 + "\n")

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=["ssh", "handshake", "check"],
            output=output,
            output_file=output_file,
            success=True,
            message=f"SSH {'is' if is_open else 'is not'} available on {self.target}"
        )

    async def _try_ssh_handshake(self) -> Tuple[bool, str]:
        """Attempt SSH handshake with the target"""
        # Use the ssh command with timeout and disable strict host key checking
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            f"user@{self.target}",
            "exit"
        ]

        success, output = await self._executor.execute(cmd)

        # Check the output for SSH information
        ssh_version = "Unknown"
        if output:
            # Try to extract SSH version
            ssh_match = re.search(r'SSH-\d+\.\d+-([^\s]+)', output)
            if ssh_match:
                ssh_version = ssh_match.group(1)

        # Return whether SSH seems to be open and the version if detected
        if "Connection refused" in output:
            return False, "Connection refused"
        elif "timed out" in output:
            return False, "Connection timed out"
        elif "ssh_exchange_identification" in output:
            return True, ssh_version
        elif "Permission denied" in output:
            return True, ssh_version

        return False, "SSH handshake failed or inconclusive"


###########################################
# Nmap Scanner Classes                    #
###########################################

class StealthLevel(enum.Enum):
    """Stealth level for Nmap scans"""
    VERY_STEALTHY = 0
    STEALTHY = 1
    BALANCED = 2
    AGGRESSIVE = 3
    VERY_AGGRESSIVE = 4

    def __str__(self):
        return self.name.replace("_", " ").title()


class ScanSpeed(enum.Enum):
    """Scan speed for Nmap scans"""
    PARANOID = 0    # T0
    SNEAKY = 1      # T1
    POLITE = 2      # T2
    NORMAL = 3      # T3
    AGGRESSIVE = 4  # T4
    INSANE = 5      # T5

    def __str__(self):
        return self.name.title()

    @property
    def timing_option(self):
        return f"-T{self.value}"


class NmapPreferences:
    """Preferences for Nmap scans"""

    def __init__(self,
                 stealth_level: StealthLevel = StealthLevel.BALANCED,
                 scan_speed: ScanSpeed = ScanSpeed.NORMAL,
                 service_detection: bool = True,
                 os_detection: bool = False,
                 script_scan: bool = True):
        self.__stealth_level = stealth_level
        self.__scan_speed = scan_speed
        self.__service_detection = service_detection
        self.__os_detection = os_detection
        self.__script_scan = script_scan

    @property
    def stealth_level(self) -> StealthLevel:
        """Get stealth level"""
        return self.__stealth_level

    @property
    def scan_speed(self) -> ScanSpeed:
        """Get scan speed"""
        return self.__scan_speed

    @property
    def service_detection(self) -> bool:
        """Get service detection flag"""
        return self.__service_detection

    @property
    def os_detection(self) -> bool:
        """Get OS detection flag"""
        return self.__os_detection

    @property
    def script_scan(self) -> bool:
        """Get script scan flag"""
        return self.__script_scan

    def get_timing_options(self) -> List[str]:
        """Get timing options for Nmap based on preferences"""
        return [self.__scan_speed.timing_option]

    def get_smb_scripts(self) -> List[str]:
        """Get appropriate SMB scripts based on stealth level"""
        # Basic scripts always included
        basic_scripts = ["smb-protocols", "smb-security-mode"]

        # Enum scripts - slightly more noisy
        enum_scripts = ["smb-enum-shares", "smb-enum-users", "smb-enum-sessions"]

        # System info scripts - more information but potentially more noisy
        info_scripts = ["smb-os-discovery", "smb-system-info"]

        # Vulnerability scripts - noisy and potentially detected by security systems
        vuln_scripts = ["smb-vuln-ms17-010", "smb-vuln-cve-2017-7494",
                        "smb-double-pulsar-backdoor"]

        # Advanced vulnerability scripts - very noisy and potentially disruptive
        advanced_vuln_scripts = ["smb-brute", "smb-vuln*"]

        if self.__stealth_level == StealthLevel.VERY_STEALTHY:
            return basic_scripts
        elif self.__stealth_level == StealthLevel.STEALTHY:
            return basic_scripts + enum_scripts
        elif self.__stealth_level == StealthLevel.BALANCED:
            return basic_scripts + enum_scripts + info_scripts
        elif self.__stealth_level == StealthLevel.AGGRESSIVE:
            return basic_scripts + enum_scripts + info_scripts + vuln_scripts
        else:  # VERY_AGGRESSIVE
            return basic_scripts + enum_scripts + info_scripts + vuln_scripts + advanced_vuln_scripts

    def get_scan_options(self) -> List[str]:
        """Get scan options based on preferences"""
        options = []

        # Add timing options
        options.extend(self.get_timing_options())

        # Add service detection if enabled
        if self.__service_detection:
            options.append("-sV")

        # Add OS detection if enabled
        if self.__os_detection:
            options.append("-O")

        # Adjust scan options based on stealth level
        if self.__stealth_level == StealthLevel.VERY_STEALTHY:
            options.extend(["-sS", "--max-retries", "1", "--min-rate", "10"])
        elif self.__stealth_level == StealthLevel.STEALTHY:
            options.extend(["-sS", "--max-retries", "2", "--min-rate", "50"])
        elif self.__stealth_level == StealthLevel.BALANCED:
            # Default Nmap options are good for balanced
            pass
        elif self.__stealth_level == StealthLevel.AGGRESSIVE:
            options.extend(["--min-rate", "300", "--max-retries", "3"])
        else:  # VERY_AGGRESSIVE
            options.extend(["--min-rate", "1000", "--max-retries", "2"])

        return options


class NmapScanner(NetworkScanner):
    """Base Nmap scanner implementation"""

    @property
    def name(self) -> str:
        return "nmap"

    async def scan(self) -> CommandScanResult:
        """Run Nmap SMB scan"""
        scripts = ["smb-enum-shares.nse", "smb-enum-users.nse", "smb-vuln-ms17-010.nse",
                   "smb-protocols.nse", "smb-security-mode.nse"]

        cmd = ["nmap", "-p139,445", f"--script={','.join(scripts)}", self.target]

        output_file = self.get_output_file()
        success, output = await self._executor.execute(cmd, output_file)

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Nmap scan completed successfully" if success else "Nmap scan failed"
        )

    async def parse_results(self, output_file: str) -> SMBInfo:
        """Parse Nmap results for SMB information"""
        info = SMBInfo()

        try:
            async with aiofiles.open(output_file, "r") as f:
                content = await f.read()

                # Extract shares
                if "smb-enum-shares" in content:
                    share_lines = content.split("smb-enum-shares:")[1].split("smb-enum-users")[0]
                    for line in share_lines.split("\n"):
                        if "\\\\" in line and "\\\\IPC$" not in line:
                            share_name = line.split("\\\\")[1].strip()
                            info.add_share(ShareInfo(name=share_name))

                # Extract users
                if "smb-enum-users" in content:
                    user_lines = content.split("smb-enum-users:")[1].split("smb-vuln")[0]
                    for line in user_lines.split("\n"):
                        if "user:" in line:
                            user_name = line.split("user:")[1].strip()
                            info.add_user(user_name)

                # Extract vulnerabilities
                if "smb-vuln" in content:
                    vuln_lines = content.split("smb-vuln")[1:]
                    for vuln_section in vuln_lines:
                        vuln_name = vuln_section.split(":")[0].strip()
                        if "VULNERABLE" in vuln_section:
                            info.add_vulnerability(vuln_name)

                # Extract SMB protocol info
                if "smb-protocols" in content:
                    proto_lines = content.split("smb-protocols:")[1].split("smb-security-mode")[0]
                    for line in proto_lines.split("\n"):
                        if "SMBv" in line:
                            info.add_protocol(line.strip())

                # Extract OS info
                if "OS details:" in content:
                    os_line = content.split("OS details:")[1].split("\n")[0].strip()
                    info.update_os_info({"os_details": os_line})

        except Exception as e:
            self._logger.error(f"Error parsing Nmap results: {e}")

        return info


class EnhancedNmapScanner(NmapScanner):
    """Enhanced Nmap scanner with flexible configuration options"""

    def __init__(self, target: str, config: ScannerConfig,
                 credential: Optional[Credential] = None,
                 results_dir: str = "recon_results",
                 preferences: Optional[NmapPreferences] = None):
        super().__init__(target, config, credential, results_dir)
        self.__preferences = preferences or NmapPreferences()

    @property
    def name(self) -> str:
        return "enhanced_nmap"

    @property
    def preferences(self) -> NmapPreferences:
        """Get scan preferences"""
        return self.__preferences

    async def scan(self, additional_options: Optional[str] = None) -> CommandScanResult:
        """Run enhanced Nmap scan with configured preferences"""
        # Start with basic command
        cmd = ["nmap", "-p139,445"]

        # Add options from preferences
        cmd.extend(self.__preferences.get_scan_options())

        # Add script scan if enabled
        if self.__preferences.script_scan:
            scripts = self.__preferences.get_smb_scripts()
            if scripts:
                cmd.extend([f"--script={','.join(scripts)}"])

        # Add any additional options
        if additional_options:
            cmd.extend(additional_options.split())

        # Add the target
        cmd.append(self.target)

        # Run the scan
        self._logger.info(f"Running enhanced Nmap scan with {len(cmd)} options")
        output_file = self.get_output_file()
        success, output = await self._executor.execute(cmd, output_file)

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Enhanced Nmap scan completed successfully" if success else "Enhanced Nmap scan failed"
        )


class StealthyNmapScanner(EnhancedNmapScanner):
    """Class for fast and stealthy Nmap scans"""

    def __init__(self, target: str, config: ScannerConfig,
                 credential: Optional[Credential] = None,
                 results_dir: str = "recon_results"):
        # Configure stealthy preferences
        preferences = NmapPreferences(
            stealth_level=StealthLevel.STEALTHY,
            scan_speed=ScanSpeed.SNEAKY,
            service_detection=True,
            os_detection=False,
            script_scan=False  # No scripts for stealthy scan
        )

        super().__init__(target, config, credential, results_dir, preferences)

    @property
    def name(self) -> str:
        return "stealthy_nmap"

    async def scan(self) -> CommandScanResult:
        """Run a fast, stealthy Nmap scan"""
        # Override with specific stealth options
        cmd = [
            "nmap",
            "-sS",               # SYN Stealth scan
            "-Pn",               # Skip host discovery
            "--open",            # Only show open ports
            "-n",                # No DNS resolution
            "--max-retries", "1",  # Minimal retries
            "--host-timeout", "30s",  # Quick timeout
            "-F",                # Fast mode - fewer ports
            self.target
        ]

        output_file = self.get_output_file()
        success, output = await self._executor.execute(cmd, output_file)

        # Parse and print results
        if success and output:
            # Extract open ports
            open_ports = []
            for line in output.splitlines():
                if "open" in line and "/tcp" in line:
                    port_match = re.search(r'(\d+)/tcp\s+open\s+(\S+)?', line)
                    if port_match:
                        port_num = port_match.group(1)
                        service = port_match.group(2) if port_match.group(2) else "unknown"
                        open_ports.append((port_num, service))

            # Print results
            print("\nStealthy Nmap Scan Results:")
            print("-" * 50)
            print(f"Target: {self.target}")
            print(f"Open Ports: {len(open_ports)}")

            if open_ports:
                print("\nPort  Service")
                print("----- -------")
                for port, service in open_ports:
                    print(f"{port.ljust(5)} {service}")

            print("-" * 50 + "\n")

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Stealthy Nmap scan completed successfully" if success else "Stealthy Nmap scan failed"
        )


###########################################
# SMB Scanner Classes                     #
###########################################

class SMBScanner(BaseScanner):
    """Base class for SMB scanners"""

    @asynccontextmanager
    async def smb_connection(self, dialect=None):
        """Context manager for SMB connections"""
        username = self.credential.username if self.credential else ""
        password = self.credential.password if self.credential else ""

        conn = SMBConnection(
            username,
            password,
            "my_machine",
            self.target,
            use_ntlm_v2=True
        )

        if dialect:
            conn.preferred_dialect = dialect

        connected = False
        try:
            # Try both SMB ports
            for port in [445, 139]:
                try:
                    connected = conn.connect(self.target, port)
                    if connected:
                        break
                except Exception as e:
                    self._logger.debug(f"Failed to connect on port {port}: {e}")

            if connected:
                yield conn
            else:
                self._logger.error(f"Failed to connect to {self.target}")
                yield None
        finally:
            if connected:
                try:
                    conn.close()
                except Exception as e:
                    self._logger.error(f"Error closing connection: {e}")


class Enum4LinuxScanner(SMBScanner):
    """Enum4Linux scanner implementation"""

    @property
    def name(self) -> str:
        return "enum4linux"

    async def scan(self) -> CommandScanResult:
        """Run Enum4Linux scan"""
        cmd = ["enum4linux", "-a", self.target]

        if self.credential:
            cmd.extend(["-u", self.credential.username, "-p", self.credential.password])

        output_file = self.get_output_file()
        success, output = await self._executor.execute(cmd, output_file)

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="Enum4Linux scan completed successfully" if success else "Enum4Linux scan failed"
        )

    async def parse_results(self, output_file: str) -> SMBInfo:
        """Parse enum4linux results"""
        info = SMBInfo()

        try:
            async with aiofiles.open(output_file, "r") as f:
                content = await f.read()

                # Extract shares
                if "Share Enumeration" in content:
                    share_lines = content.split("Share Enumeration")[1].split("Password Policy")[0]
                    for line in share_lines.split("\n"):
                        if "Sharename" in line and "Type" in line:
                            continue
                        if "---" in line:
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            share_name = parts[0].strip()
                            if share_name and share_name != "":
                                info.add_share(ShareInfo(name=share_name))

                # Extract users
                if "user:[" in content:
                    user_lines = [line for line in content.split("\n") if "user:[" in line]
                    for line in user_lines:
                        user_name = line.split("user:[")[1].split("]")[0].strip()
                        info.add_user(user_name)

                # Extract groups
                if "group:[" in content:
                    group_lines = [line for line in content.split("\n") if "group:[" in line]
                    for line in group_lines:
                        group_name = line.split("group:[")[1].split("]")[0].strip()
                        info.add_group(group_name)

                # Extract OS info
                if "OS=" in content:
                    os_line = [line for line in content.split("\n") if "OS=" in line]
                    if os_line:
                        info.update_os_info({"os": os_line[0].split("OS=")[1].strip()})

                if "Server=" in content:
                    server_line = [line for line in content.split("\n") if "Server=" in line]
                    if server_line:
                        info.update_os_info({"server": server_line[0].split("Server=")[1].strip()})

        except Exception as e:
            self._logger.error(f"Error parsing enum4linux results: {e}")

        return info


class SMBMapScanner(SMBScanner):
    """SMBMap scanner implementation"""

    @property
    def name(self) -> str:
        return "smbmap"

    async def scan(self) -> CommandScanResult:
        """Run SMBMap scan"""
        cmd = ["smbmap", "-H", self.target]

        if self.credential:
            cmd.extend(["-u", self.credential.username, "-p", self.credential.password])

        output_file = self.get_output_file()
        success, output = await self._executor.execute(cmd, output_file)

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="SMBMap scan completed successfully" if success else "SMBMap scan failed"
        )

    async def parse_results(self, output_file: str) -> SMBInfo:
        """Parse SMBMap results"""
        info = SMBInfo()

        try:
            async with aiofiles.open(output_file, "r") as f:
                content = await f.read()

                for line in content.split("\n"):
                    if line.strip() and not line.startswith("[+]") and not line.startswith("[-]"):
                        parts = [p.strip() for p in line.split() if p.strip()]
                        if len(parts) >= 3:
                            share_name = parts[0]
                            permissions = parts[1]
                            comment = " ".join(parts[2:])

                            share = ShareInfo(name=share_name, comment=comment)
                            info.add_share(share)

        except Exception as e:
            self._logger.error(f"Error parsing SMBMap results: {e}")

        return info


class PySMBScanner(SMBScanner):
    """PySMB direct API scanner implementation"""

    @property
    def name(self) -> str:
        return "pysmb"

    async def scan(self) -> ScanResult:
        """Run PySMB scan"""
        output_file = self.get_output_file()
        success = False
        results = []

        # Try different SMB dialects
        for dialect in ["SMB2", "SMB3", None]:  # None = default/auto-negotiate
            try:
                async with self.smb_connection(dialect=dialect) as conn:
                    if not conn:
                        continue

                    shares = conn.listShares()
                    dialect_output_file = self.get_output_file(f"_{dialect or 'default'}")

                    share_info = []
                    for share in shares:
                        share_data = ShareInfo(
                            name=share.name,
                            comment=share.comments,
                            share_type=str(share.type)
                        )

                        # Try to list files in share
                        try:
                            files = conn.listPath(share.name, '/')
                            share_data.files = [f.filename for f in files if f.filename not in ['.', '..']][:10]
                        except Exception as e:
                            share_data.access_error = str(e)

                        share_info.append(share_data)

                    # Write results to file
                    async with aiofiles.open(dialect_output_file, "w") as f:
                        for share in share_info:
                            await f.write(f"Share: {share.name}, Comment: {share.comment}, Type: {share.type}\n")
                            if share.files:
                                await f.write(f"  Files: {', '.join(share.files)}\n")
                            elif share.access_error:
                                await f.write(f"  Error listing files: {share.access_error}\n")

                    results.append({
                        "dialect": dialect or "default",
                        "shares": [s.to_dict() for s in share_info]
                    })

                    success = True
                    self._logger.info(f"Successfully enumerated shares with dialect {dialect or 'default'}")
                    break  # If successful, don't try other dialects

            except Exception as e:
                self._logger.error(f"PySMB scan failed with dialect {dialect or 'default'}: {e}")

        # Write combined results
        if results:
            async with aiofiles.open(output_file, "w") as f:
                await f.write(json.dumps(results, indent=2))

        return ScanResult(
            target=self.target,
            scanner_name=self.name,
            success=success,
            message="Successfully enumerated shares" if success else "Failed to enumerate shares",
            output_file=output_file
        )

    async def get_smb_info(self) -> SMBInfo:
        """Get SMB information directly from PySMB scanning"""
        info = SMBInfo()

        try:
            # Try different SMB dialects
            for dialect in ["SMB2", "SMB3", None]:  # None = default/auto-negotiate
                async with self.smb_connection(dialect=dialect) as conn:
                    if not conn:
                        continue

                    # Got a connection, save the working dialect
                    info.dialect = dialect or "default"

                    # List shares
                    shares = conn.listShares()
                    for share in shares:
                        share_info = ShareInfo(
                            name=share.name,
                            comment=share.comments,
                            share_type=str(share.type)
                        )

                        # Try to list files in share
                        try:
                            files = conn.listPath(share.name, '/')
                            share_info.files = [f.filename for f in files if f.filename not in ['.', '..']][:10]
                        except Exception as e:
                            share_info.access_error = str(e)

                        info.add_share(share_info)

                    break  # If we get here, we succeeded, so stop trying dialects
        except Exception as e:
            self._logger.error(f"Error getting SMB info via PySMB: {e}")

        return info


class CrackMapExecScanner(SMBScanner):
    """CrackMapExec scanner implementation"""

    @property
    def name(self) -> str:
        return "crackmapexec"

    async def scan(self) -> CommandScanResult:
        """Run CrackMapExec scan"""
        cmd = ["crackmapexec", "smb", self.target]

        if self.credential:
            cmd.extend(["-u", self.credential.username, "-p", self.credential.password])

        output_file = self.get_output_file()
        success, output = await self._executor.execute(cmd, output_file)

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="CrackMapExec scan completed successfully" if success else "CrackMapExec scan failed"
        )


class ImpacketSecretsDumpScanner(SMBScanner):
    """Impacket SecretsDump scanner implementation"""

    @property
    def name(self) -> str:
        return "secretsdump"

    async def scan(self) -> CommandScanResult:
        """Run Impacket SecretsDump scan"""
        if not self.credential:
            return CommandScanResult(
                target=self.target,
                scanner_name=self.name,
                command=[],
                success=False,
                message="No credentials provided for SecretsDump scan"
            )

        username = self.credential.username or "guest"
        password = self.credential.password or ""

        cmd = ["secretsdump.py", f"{username}:{password}@{self.target}"]
        output_file = self.get_output_file()
        success, output = await self._executor.execute(cmd, output_file)

        return CommandScanResult(
            target=self.target,
            scanner_name=self.name,
            command=cmd,
            output=output,
            output_file=output_file,
            success=success,
            message="SecretsDump completed successfully" if success else "SecretsDump failed"
        )


###########################################
# Web Scanner Classes                     #
###########################################

class WebScanner(BaseScanner):
    """Base class for web scanners"""

    def __init__(self, target: str, config: ScannerConfig,
                 results_dir: str = "recon_results",
                 max_depth: int = 2,
                 respect_robots: bool = True,
                 rate_limit: float = 1.0):  # requests per second
        super().__init__(target, config, None, results_dir)
        self._max_depth = max_depth
        self._respect_robots = respect_robots
        self._rate_limit = rate_limit
        self._visited_urls = set()
        self._disallowed_paths = set()
        self._last_request_time = 0

    async def _get_headers(self) -> Dict[str, str]:
        """Get request headers including user agent"""
        return {
            "User-Agent": "Network-Recon-Framework/1.0 (Research-Scanner; +https://example.com/about/scanner)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

    async def _check_robots_txt(self, session: aiohttp.ClientSession) -> bool:
        """Check robots.txt for scanning permissions"""
        try:
            # Get base URL
            parsed_url = urllib.parse.urlparse(self.target)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            robots_url = f"{base_url}/robots.txt"

            async with session.get(robots_url, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()

                    # Parse robots.txt content
                    user_agent = None
                    for line in content.split('\n'):
                        line = line.strip().lower()

                        # Check for user agent line
                        if line.startswith('user-agent:'):
                            agent = line[11:].strip()
                            if agent == '*' or 'bot' in agent:
                                user_agent = agent

                        # Check for disallow line
                        elif user_agent and line.startswith('disallow:'):
                            path = line[9:].strip()
                            if path:
                                self._disallowed_paths.add(path)

                    # Check if our target path is allowed
                    target_path = parsed_url.path
                    for path in self._disallowed_paths:
                        if target_path.startswith(path):
                            self._logger.warning(f"Target path {target_path} is disallowed by robots.txt")
                            return False

                    return True
                else:
                    # No robots.txt or can't access it, assume allowed
                    return True
        except Exception as e:
            self._logger.error(f"Error checking robots.txt: {e}")
            # Assume allowed if there's an error
            return True

    async def _is_allowed(self, url: str) -> bool:
        """Check if a URL is allowed to be scanned"""
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path

        for disallowed in self._disallowed_paths:
            if path.startswith(disallowed):
                return False

        return True

    async def _rate_limit_request(self) -> None:
        """Implement rate limiting for requests"""
        current_time = time.time()
        time_since_last = current_time - self._last_request_time
        sleep_time = max(0, (1.0 / self._rate_limit) - time_since_last)

        if sleep_time > 0:
            await asyncio.sleep(sleep_time)

        self._last_request_time = time.time()

    async def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize a URL (handle relative URLs, etc.)"""
        if not url:
            return None

        # Skip javascript: URLs, anchors, etc.
        if url.startswith(('javascript:', '#', 'mailto:', 'tel:')):
            return None

        # Handle relative URLs
        if not url.startswith(('http://', 'https://')):
            return urllib.parse.urljoin(base_url, url)

        # Check if URL is for the same domain
        parsed_base = urllib.parse.urlparse(base_url)
        parsed_url = urllib.parse.urlparse(url)

        if parsed_base.netloc != parsed_url.netloc:
            return None  # Skip external domains

        return url


class APIEndpointScanner(WebScanner):
    """Scanner to identify potential API endpoints in web content"""

    def __init__(self, target: str, config: ScannerConfig,
                 results_dir: str = "recon_results",
                 max_depth: int = 2,
                 respect_robots: bool = True,
                 rate_limit: float = 1.0):
        super().__init__(target, config, results_dir, max_depth, respect_robots, rate_limit)
        self._discovered_endpoints = set()
        self._potential_api_paths = set()
        self._api_patterns = [
            r'/api/\w+/?',                  # Standard API paths
            r'/v\d+/\w+/?',                 # Versioned API paths
            r'/rest/\w+/?',                 # REST API paths
            r'/graphql/?',                  # GraphQL endpoints
            r'/swagger/?',                  # Swagger documentation
            r'/openapi/?',                  # OpenAPI documentation
            r'\.json(\?|$)',                # JSON responses
            r'\.xml(\?|$)',                 # XML responses
            r'/oauth/\w+/?',                # OAuth endpoints
            r'/auth/\w+/?',                 # Auth endpoints
            r'/service/\w+/?',              # Service endpoints
            r'/data/\w+/?',                 # Data endpoints
            r'/ajax/\w+/?',                 # AJAX endpoints
            r'/rpc/\w+/?',                  # RPC endpoints
            r'/_api/\w+/?',                 # Hidden API endpoints
            r'/wp-json/\w+/?',              # WordPress REST API
            r'/api-docs/?',                 # API documentation
        ]

    @property
    def name(self) -> str:
        return "api_endpoint_scanner"

    @property
    def discovered_endpoints(self) -> Set[str]:
        """Get discovered endpoints"""
        return self._discovered_endpoints

    async def scan(self) -> ScanResult:
        """Scan target website for API endpoints"""
        output_file = self.get_output_file()

        # Ensure target is a URL
        if not self.target.startswith(('http://', 'https://')):
            self.target = f"https://{self.target}"

        # Create aiohttp session
        async with aiohttp.ClientSession(headers=await self._get_headers()) as session:
            # Check robots.txt if required
            if self._respect_robots and not await self._check_robots_txt(session):
                return ScanResult(
                    target=self.target,
                    scanner_name=self.name,
                    success=False,
                    message="Scanning not allowed by robots.txt",
                    output_file=None
                )

            # Create network graph for visualization
            graph = nx.DiGraph()
            graph.add_node(self.target, type="root")

            # Start crawling from the main page
            await self._crawl_page(session, self.target, 0, graph)

            # Check potential API paths
            await self._test_potential_api_paths(session)

            # Visualize the API endpoint graph
            graph_image = await self._generate_graph_image(graph)

            # Write results to file
            await self._write_results(output_file, graph_image)

            # Print summary
            self._print_summary()

        return ScanResult(
            target=self.target,
            scanner_name=self.name,
            success=True,
            message=f"Discovered {len(self._discovered_endpoints)} potential API endpoints",
            output_file=output_file
        )

    async def _crawl_page(self, session: aiohttp.ClientSession, url: str, depth: int, graph: nx.DiGraph) -> None:
        """Crawl a page and extract API endpoints"""
        if depth > self._max_depth or url in self._visited_urls:
            return

        if not await self._is_allowed(url):
            return

        self._visited_urls.add(url)

        try:
            await self._rate_limit_request()

            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    return

                content_type = response.headers.get('Content-Type', '')
                if not content_type.startswith('text/html'):
                    return

                html_content = await response.text()

                # Extract API endpoints from HTML
                api_endpoints = await self._extract_api_endpoints(html_content, url)
                for endpoint in api_endpoints:
                    self._discovered_endpoints.add(endpoint)
                    graph.add_node(endpoint, type="api")
                    graph.add_edge(url, endpoint)

                # Extract links for further crawling
                soup = BeautifulSoup(html_content, 'html.parser')
                links = soup.find_all('a', href=True)

                for link in links:
                    href = link.get('href')
                    normalized_url = await self._normalize_url(href, url)

                    if normalized_url and normalized_url not in self._visited_urls:
                        if depth < self._max_depth:
                            graph.add_node(normalized_url, type="page")
                            graph.add_edge(url, normalized_url)
                            await self._crawl_page(session, normalized_url, depth + 1, graph)

                # Extract and analyze JavaScript files
                script_tags = soup.find_all('script', src=True)
                for script in script_tags:
                    script_url = await self._normalize_url(script.get('src'), url)
                    if script_url and script_url not in self._visited_urls:
                        self._visited_urls.add(script_url)
                        api_endpoints = await self._analyze_javascript(session, script_url, url)

                        for endpoint in api_endpoints:
                            self._discovered_endpoints.add(endpoint)
                            graph.add_node(endpoint, type="api")
                            graph.add_edge(script_url, endpoint)

                        # Add script node to graph
                        graph.add_node(script_url, type="script")
                        graph.add_edge(url, script_url)

        except Exception as e:
            self._logger.error(f"Error crawling {url}: {e}")

    async def _extract_api_endpoints(self, html_content: str, base_url: str) -> Set[str]:
        """Extract potential API endpoints from HTML content"""
        endpoints = set()

        # Look for API URLs in the HTML
        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract from data attributes
        for tag in soup.find_all(attrs={"data-url": True}):
            url = tag.get('data-url')
            normalized_url = await self._normalize_url(url, base_url)
            if normalized_url:
                for pattern in self._api_patterns:
                    if re.search(pattern, normalized_url):
                        endpoints.add(normalized_url)
                        break

        # Extract from JavaScript inline code
        for script in soup.find_all('script'):
            if script.string:
                # Look for API URLs in JavaScript code
                js_code = script.string
                # Fetch URLs from JavaScript
                urls = re.findall(r'["\'](?:(?:https?://)|/)(?:[^"\'/\s]+/?)+["\']', js_code)

                for url in urls:
                    # Clean up the URL (remove quotes)
                    url = url.strip('\'"')
                    normalized_url = await self._normalize_url(url, base_url)

                    if normalized_url:
                        for pattern in self._api_patterns:
                            if re.search(pattern, normalized_url):
                                endpoints.add(normalized_url)
                                # Also add to potential paths for testing
                                parsed_url = urllib.parse.urlparse(normalized_url)
                                self._potential_api_paths.add(parsed_url.path)
                                break

        return endpoints

    async def _analyze_javascript(self, session: aiohttp.ClientSession, script_url: str, base_url: str) -> Set[str]:
        """Analyze JavaScript file for API endpoints"""
        endpoints = set()

        try:
            await self._rate_limit_request()

            async with session.get(script_url, timeout=10) as response:
                if response.status != 200:
                    return endpoints

                js_content = await response.text()

                # Look for URLs in JavaScript code
                urls = re.findall(r'["\'](?:(?:https?://)|/)(?:[^"\'/\s]+/?)+["\']', js_content)

                for url in urls:
                    # Clean up the URL (remove quotes)
                    url = url.strip('\'"')
                    normalized_url = await self._normalize_url(url, base_url)

                    if normalized_url:
                        for pattern in self._api_patterns:
                            if re.search(pattern, normalized_url):
                                endpoints.add(normalized_url)
                                # Also add to potential paths for testing
                                parsed_url = urllib.parse.urlparse(normalized_url)
                                self._potential_api_paths.add(parsed_url.path)
                                break

                # Advanced JavaScript parsing with esprima if available
                try:
                    ast = esprima.parseScript(js_content)
                    # Extract fetch, XHR, axios calls
                    # This would require recursive AST traversal
                    # Simplified version for demonstration
                    fetch_calls = re.findall(r'fetch\(["\']([^"\']+)["\']', js_content)
                    axios_calls = re.findall(r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']', js_content)
                    xhr_calls = re.findall(r'\.open\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']', js_content)

                    for url in fetch_calls + [match[1] for match in axios_calls] + xhr_calls:
                        normalized_url = await self._normalize_url(url, base_url)
                        if normalized_url:
                            endpoints.add(normalized_url)
                            # Also add to potential paths for testing
                            parsed_url = urllib.parse.urlparse(normalized_url)
                            self._potential_api_paths.add(parsed_url.path)

                except Exception as e:
                    self._logger.debug(f"Error parsing JavaScript with esprima: {e}")

        except Exception as e:
            self._logger.error(f"Error analyzing JavaScript {script_url}: {e}")

        return endpoints

    async def _test_potential_api_paths(self, session: aiohttp.ClientSession) -> None:
        """Test potential API paths with common HTTP methods"""
        parsed_url = urllib.parse.urlparse(self.target)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        for path in self._potential_api_paths:
            full_url = urllib.parse.urljoin(base_url, path)

            # Test with different methods
            for method in ['GET']:  # Add more methods for more thorough testing
                try:
                    await self._rate_limit_request()

                    if method == 'GET':
                        async with session.get(full_url, timeout=5) as response:
                            if response.status == 200:
                                content_type = response.headers.get('Content-Type', '')
                                if 'json' in content_type or 'xml' in content_type:
                                    self._discovered_endpoints.add(full_url)

                except Exception as e:
                    self._logger.debug(f"Error testing API path {full_url} with {method}: {e}")

    async def _generate_graph_image(self, graph: nx.DiGraph) -> str:
        """Generate a visualization of the API endpoint graph"""
        plt.figure(figsize=(12, 8))

        # Define node colors based on type
        node_colors = []
        for node in graph.nodes():
            node_type = graph.nodes[node].get('type', 'page')
            if node_type == 'root':
                node_colors.append('blue')
            elif node_type == 'page':
                node_colors.append('green')
            elif node_type == 'api':
                node_colors.append('red')
            elif node_type == 'script':
                node_colors.append('orange')
            else:
                node_colors.append('gray')

        # Draw the graph
        pos = nx.spring_layout(graph, k=0.3, iterations=50)
        nx.draw(graph, pos, with_labels=False, node_color=node_colors,
                node_size=30, edge_color='gray', linewidths=0.5,
                font_size=8, arrows=True, alpha=0.6)

        # Add legend
        import matplotlib.patches as mpatches
        root_patch = mpatches.Patch(color='blue', label='Root')
        page_patch = mpatches.Patch(color='green', label='Page')
        api_patch = mpatches.Patch(color='red', label='API Endpoint')
        script_patch = mpatches.Patch(color='orange', label='Script')
        plt.legend(handles=[root_patch, page_patch, api_patch, script_patch])

        # Save to base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png', dpi=150)
        plt.close()

        base64_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return base64_image

    async def _write_results(self, output_file: str, graph_image: str) -> None:
        """Write discovered endpoints to file"""
        result = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "discovered_endpoints": list(self._discovered_endpoints),
            "crawled_pages": len(self._visited_urls),
            "api_endpoint_count": len(self._discovered_endpoints),
            "graph_image": graph_image
        }

        async with aiofiles.open(output_file, "w") as f:
            await f.write(json.dumps(result, indent=2))

    def _print_summary(self) -> None:
        """Print a summary of the scan results"""
        print("\nAPI Endpoint Discovery Results:")
        print("-" * 50)
        print(f"Target: {self.target}")
        print(f"Pages Crawled: {len(self._visited_urls)}")
        print(f"API Endpoints Discovered: {len(self._discovered_endpoints)}")

        if len(self._discovered_endpoints) > 0:
            print("\nTop API Endpoints:")
            for endpoint in list(self._discovered_endpoints)[:5]:  # Show top 5
                print(f"  - {endpoint}")

            if len(self._discovered_endpoints) > 5:
                print(f"  ... and {len(self._discovered_endpoints) - 5} more")

        print("-" * 50 + "\n")


class ScriptAnalyzer(WebScanner):
    """Scanner to download and analyze JavaScript files"""

    def __init__(self, target: str, config: ScannerConfig,
                 results_dir: str = "recon_results",
                 max_depth: int = 2,
                 respect_robots: bool = True,
                 rate_limit: float = 1.0,
                 download_scripts: bool = True):
        super().__init__(target, config, results_dir, max_depth, respect_robots, rate_limit)
        self._downloaded_scripts = {}
        self._script_info = {}
        self._download_scripts = download_scripts
        self._script_save_dir = os.path.join(results_dir, "scripts")
        os.makedirs(self._script_save_dir, exist_ok=True)

    @property
    def name(self) -> str:
        return "script_analyzer"

    @property
    def downloaded_scripts(self) -> Dict[str, str]:
        """Get downloaded scripts"""
        return self._downloaded_scripts

    @property
    def script_info(self) -> Dict[str, ScriptInfo]:
        """Get script information"""
        return self._script_info

    async def scan(self) -> ScanResult:
        """Scan target website for scripts"""
        output_file = self.get_output_file()

        # Ensure target is a URL
        if not self.target.startswith(('http://', 'https://')):
            self.target = f"https://{self.target}"

        # Create aiohttp session
        async with aiohttp.ClientSession(headers=await self._get_headers()) as session:
            # Check robots.txt if required
            if self._respect_robots and not await self._check_robots_txt(session):
                return ScanResult(
                    target=self.target,
                    scanner_name=self.name,
                    success=False,
                    message="Scanning not allowed by robots.txt",
                    output_file=None
                )

            # Start crawling from the main page
            await self._crawl_for_scripts(session, self.target, 0)

            # Analyze all downloaded scripts
            for script_url, script_content in self._downloaded_scripts.items():
                script_info = await self._analyze_script(script_url, script_content)
                self._script_info[script_url] = script_info

            # Generate visualizations
            dependency_graph = await self._generate_dependency_graph()

            # Write results to file
            await self._write_results(output_file, dependency_graph)

            # Print summary
            self._print_summary()

        return ScanResult(
            target=self.target,
            scanner_name=self.name,
            success=True,
            message=f"Analyzed {len(self._downloaded_scripts)} JavaScript files",
            output_file=output_file
        )

    async def _crawl_for_scripts(self, session: aiohttp.ClientSession, url: str, depth: int) -> None:
        """Crawl a page and extract scripts"""
        if depth > self._max_depth or url in self._visited_urls:
            return

        if not await self._is_allowed(url):
            return

        self._visited_urls.add(url)

        try:
            await self._rate_limit_request()

            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    return

                content_type = response.headers.get('Content-Type', '')
                if not content_type.startswith('text/html'):
                    return

                html_content = await response.text()

                # Parse HTML
                soup = BeautifulSoup(html_content, 'html.parser')

                # Extract script tags
                script_tags = soup.find_all('script')

                for script in script_tags:
                    # External scripts
                    if script.get('src'):
                        script_url = await self._normalize_url(script.get('src'), url)
                        if script_url and script_url not in self._downloaded_scripts:
                            await self._download_script(session, script_url)

                    # Inline scripts
                    elif script.string and len(script.string.strip()) > 0:
                        # Generate a unique name for the inline script
                        inline_name = f"inline_{hash(script.string) & 0xffffffff}_{url.split('/')[-1]}.js"
                        inline_url = f"{url}#{inline_name}"

                        if inline_url not in self._downloaded_scripts:
                            self._downloaded_scripts[inline_url] = script.string.strip()
                            self._script_info[inline_url] = ScriptInfo(name=inline_name, content=script.string.strip())
                            self._logger.debug(f"Found inline script: {inline_url}")
                            # Save inline script to file
                            await self._save_script(inline_url, script.string.strip())
                # Extract links for further crawling
                links = soup.find_all('a', href=True)
                for link in links:
                    href = link.get('href')
                    normalized_url = await self._normalize_url(href, url)

                    if normalized_url and normalized_url not in self._visited_urls:
                        if depth < self._max_depth:
                            await self._crawl_for_scripts(session, normalized_url, depth + 1)
        except Exception as e:
            self._logger.error(f"Error crawling {url}: {e}")
    async def _download_script(self, session: aiohttp.ClientSession, script_url: str) -> None:
        """Download a JavaScript file and save it"""
        try:
            await self._rate_limit_request()

            async with session.get(script_url, timeout=10) as response:
                if response.status == 200:
                    script_content = await response.text()
                    self._downloaded_scripts[script_url] = script_content
                    self._logger.debug(f"Downloaded script: {script_url}")

                    # Save the script to a file
                    await self._save_script(script_url, script_content)
                else:
                    self._logger.warning(f"Failed to download {script_url}: {response.status}")
        except Exception as e:
            self._logger.error(f"Error downloading script {script_url}: {e}")
            self._downloaded_scripts[script_url] = None
            self._script_info[script_url] = ScriptInfo(name=script_url, content=None)
    async def _save_script(self, script_url: str, content: str) -> None:
        """Save the script content to a file"""
        try:
            parsed_url = urllib.parse.urlparse(script_url)
            script_name = os.path.basename(parsed_url.path) or f"script_{hash(script_url) & 0xffffffff}.js"
            script_path = os.path.join(self._script_save_dir, script_name)

            async with aiofiles.open(script_path, "w") as f:
                await f.write(content)

            self._logger.debug(f"Saved script to {script_path}")
        except Exception as e:
            self._logger.error(f"Error saving script {script_url}: {e}")
            self._downloaded_scripts[script_url] = None
            self._script_info[script_url] = ScriptInfo(name=script_url, content=None)
    async def _analyze_script(self, script_url: str, script_content: str) -> ScriptInfo:
        """Analyze a JavaScript file for potential vulnerabilities"""
        script_info = ScriptInfo(name=script_url, content=script_content)

        # Check for common vulnerabilities
        if "eval(" in script_content:
            script_info.vulnerabilities.append("eval() usage detected")

        if "document.cookie" in script_content:
            script_info.vulnerabilities.append("Potential cookie exposure")

        # Add more analysis as needed

        return script_info
    def create_api_endpoint_chart(self, targets: Optional[List[str]] = None) -> Dict:
        """Create a chart showing API endpoints by target"""
    if not targets:
        targets = list(self.__metrics['api_endpoints'].keys())

    # Count API endpoints for each target
    endpoint_counts = {target: len(endpoints) for target, endpoints in self.__metrics['api_endpoints'].items()
                       if target in targets and endpoints}

    if not endpoint_counts:
        logging.waring("[-] No API endpoints found for the specified targets.")
        print(f"[-] API endpoints chart not created due to lack of data.")

    # Sort data for better visualization
    sorted_items = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)
    sorted_targets = [item[0] for item in sorted_items]
    sorted_counts = [item[1] for item in sorted_items]

    # Create bar chart

def create_vulnerability_summary(self, targets: Optional[List[str]] = None) -> Dict:
    """Create a summary chart of vulnerabilities by severity across targets"""
    if not targets:
        targets = list(self.__metrics['vulnerabilities'].keys())

    # Collect vulnerability data
    severity_levels = ['Critical', 'High', 'Medium', 'Low', 'Info']
    vuln_data = {level: [] for level in severity_levels}

    for target in targets:
        if target in self.__metrics['vulnerabilities']:
            target_vulns = self.__metrics['vulnerabilities'][target]

            # Count vulnerabilities by severity for this target
            for level in severity_levels:
                count = sum(1 for v in target_vulns if v.get('severity', '').lower() == level.lower())
                vuln_data[level].append(count)
        else:
            # No vulnerability data for this target
            for level in severity_levels:
                vuln_data[level].append(0)

    # Create stacked bar chart
    fig = go.Figure()


    for level in severity_levels:
        fig.add_trace(go.Bar(
            name=level,
            x=targets,
            y=vuln_data[level],
            marker_color=colors[level]
        ))

    fig.update_layout(
        title="Vulnerabilities by Severity Across Targets",
        xaxis_title="Target",
        yaxis_title="Number of Vulnerabilities",
        barmode='stack',
        template="plotly_white",
        legend_title="Severity"
    )

    # Save to output directory
    output_file = os.path.join(self.__output_dir, "vulnerability_summary.html")
    pio.write_html(fig, file=output_file, auto_open=False)

    # Convert to base64 for embedding in reports
    img_bytes = fig.to_image(format="png")
    img_base64 = base64.b64encode(img_bytes).decode('utf-8')

    result = {
        'html_file': output_file,
        'base64_image': img_base64,
        'chart_type': 'stacked_bar',
        'title': 'Vulnerabilities by Severity Across Targets'
    }

    self.__report_data['vulnerability_summary'] = result
    return result
        # Generate graph image
    img_bytes = fi

