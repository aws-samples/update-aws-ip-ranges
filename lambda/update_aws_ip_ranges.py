'''
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
'''

import hashlib
import json
import logging
import os
import time
import ipaddress
from urllib import request
from datetime import datetime, timezone
from typing import Any, Dict, Union
from dataclasses import dataclass, field, asdict

import boto3 # type: ignore

####

@dataclass
class IPv4List():
    """List of IPv4 Networks"""

    ip_list: list[str] = field(default_factory=list)
    __summarized_ip_list: list[str] = field(default_factory=list)

    def summarized(self) -> list[str]:
        """Summarize this list as IPv4 network and sort it"""
        if not self.__summarized_ip_list:
            if len(self.ip_list) == 1:
                return self.ip_list

            summarized_sorted = sorted(
                ipaddress.collapse_addresses(
                    [ipaddress.IPv4Network(addr) for addr in self.ip_list]
                )
            )
            self.__summarized_ip_list = [net.with_prefixlen for net in summarized_sorted]
        return self.__summarized_ip_list

    def sort(self) -> None:
        """Sort this list as IPv4 network"""
        if len(self.ip_list) > 1:
            self.ip_list = sorted(self.ip_list, key = ipaddress.IPv4Network)

    def asdict(self) -> Dict:
        """Return a dictionary from this object"""
        return asdict(self)

@dataclass
class IPv6List():
    """List of IPv6 Networks"""

    ip_list: list[str] = field(default_factory=list)
    __summarized_ip_list: list[str] = field(default_factory=list)

    def summarized(self) -> list[str]:
        """Summarize this list as IPv6 network and sort it"""
        if not self.__summarized_ip_list:
            if len(self.ip_list) == 1:
                return self.ip_list

            summarized_sorted = sorted(
                ipaddress.collapse_addresses(
                    [ipaddress.IPv6Network(addr) for addr in self.ip_list]
                )
            )
            self.__summarized_ip_list = [net.with_prefixlen for net in summarized_sorted]
        return self.__summarized_ip_list

    def sort(self) -> None:
        """Sort this list as IPv6 network"""
        if len(self.ip_list) > 1:
            self.ip_list = sorted(self.ip_list, key = ipaddress.IPv6Network)

    def asdict(self) -> Dict:
        """Return a dictionary from this object"""
        return asdict(self)

@dataclass
class ServiceIPRange():
    """Store IPv4 and IPv6 networks"""
    ipv4: IPv4List = field(default_factory=IPv4List)
    ipv6: IPv6List = field(default_factory=IPv6List)

    def asdict(self) -> Dict[str, Union[IPv4List, IPv6List]]:
        """Return a dictionary from this object"""
        return {'ipv4': self.ipv4, 'ipv6': self.ipv6}


DESCRIPTION = 'Managed by auto update IP ranges Lambda'

####### Get values from environment variables  ######

## Logging level options in less verbosity order. INFO is the default.
## If you enable DEBUG, it will log boto3 calls as well.
# CRITICAL
# ERROR
# WARNING
# INFO
# DEBUG

# Get logging level from environment variable
LOG_LEVEL = os.getenv('LOG_LEVEL', '').upper()
if LOG_LEVEL not in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
    LOG_LEVEL = 'INFO'

# Set up logging. Set the level if the handler is already configured.
if len(logging.getLogger().handlers) > 0:
    logging.getLogger().setLevel(LOG_LEVEL)
else:
    logging.basicConfig(level=LOG_LEVEL)

# Define client for services
waf_client = boto3.client('wafv2')
ec2_client = boto3.client('ec2')


#### Main Lambda function
def lambda_handler(event, context):
    """Lambda function handler"""
    logging.info('lambda_handler start')
    logging.debug(f'Parameter event: {event}')
    logging.debug(f'Parameter context: {context}')
    try:
        # Read config file to get services and regions
        with open('services.json', 'r', encoding='utf-8') as services_file:
            logging.info('Reading file "services.json"')
            config_services: Dict[str, Any] = json.loads(services_file.read())
            logging.info(f'Found services: {config_services}')

        # If you want different services, set the SERVICES environment variable
        # It defaults to ROUTE53_HEALTHCHECKS, API_GATEWAY and EC2_INSTANCE_CONNECT.
        # Using 'jq' and 'curl' get the list of possible services like this:
        # curl -s 'https://ip-ranges.amazonaws.com/ip-ranges.json' | jq -r '.prefixes[] | .service' ip-ranges.json | sort -u

        message: Dict[str, Any] = json.loads(event['Records'][0]['Sns']['Message'])
        logging.debug(f'Message from SNS topic: {message}')

        # Load the ip ranges from the url
        logging.debug(f'URL: {message["url"]}')
        logging.debug(f'MD5: {message["md5"]}')
        ip_ranges: Dict[str, Any] = json.loads(get_ip_groups_json(message['url'], message['md5']))
        logging.info('Got "ip-ranges.json" file')
        logging.info(f'SyncToken: {ip_ranges["syncToken"]}')
        logging.info(f'CreateDate: {ip_ranges["createDate"]}')
        logging.debug(f'File content: {ip_ranges}')

        # Extract the service ranges
        # Each service name from config file will be a key on returned dictionary
        # service_ranges => Dict(string, Dict(string, List))
        # keys 'ipv4' and 'ipv6' will ALWAYS be a valid list.
        # If no IP range is found, it will be an empty list
        # Example:
        # {
        #     'CLOUDFRONT': {
        #         'ipv4': [
        #             '1.1.1.1/32',
        #             '2.2.2.2/32'
        #         ],
        #         'ipv6': [
        #             'aaaa::1/56'
        #         ]
        #     },
        #     'API_GATEWAY': {
        #         'ipv4': [
        #             '3.3.3.3/32'
        #         ],
        #         'ipv6': []
        #     }
        # }
        service_ranges: Dict[str, ServiceIPRange] = get_ranges_for_service(ip_ranges, config_services)
        logging.info(f'Service IP ranges keys: {service_ranges.keys()}')
        logging.debug(f'Dictionary with service IP ranges: {service_ranges}')

        # Dictonary to return from this function
        resource_names: Dict[str, Dict[str, list[str]]] = {
            'PrefixList': {'created': [], 'updated':[]},
            'WafIPSet': {'created': [], 'updated':[]}
        }
        service_name: str = ''
        should_summarize: bool = False

        # Create or Update the appropriate resource for each service range found
        ### Prefix List
        logging.info('Handling VPC Prefix List')
        vpc_prefix_lists: Dict[str, Dict] = {}
        for config_service in config_services['Services']:
            service_name = config_service['Name']

            logging.info(f'Start handle VPC Prefix List for "{service_name}"')
            if service_name not in service_ranges:
                logging.warning(f'Service name "{service_name}" not found in service ranges variable. This condition should NEVER happens. Possible bug in the code. Please investigate.')
            else:
                # Handle Prefix List
                if 'PrefixList' not in config_service:
                    logging.info(f'Service "{service_name}" not configured with "PrefixList"')
                else:
                    if not config_service['PrefixList']['Enable']:
                        logging.info(f'Service "{service_name}" is configured with "PrefixList" but it is not enable')
                    else:
                        try:
                            # Will list VPC Prefix Lists only once
                            if not vpc_prefix_lists:
                                logging.info('Will get the list of VPC Prefix List for the first time')
                                vpc_prefix_lists = list_prefix_lists(ec2_client)

                            should_summarize = config_service['PrefixList']['Summarize']
                            prefix_list_names: Dict[str, list[str]] = manage_prefix_list(ec2_client, vpc_prefix_lists, service_name, service_ranges, should_summarize)
                            resource_names['PrefixList']['created'] += prefix_list_names['created']
                            resource_names['PrefixList']['updated'] += prefix_list_names['updated']
                        except Exception as error:
                            logging.error("Error handling VPC Prefix List. It will not block the execution. It will continue to other services and resources.")
                            logging.exception(error)
            logging.info(f'Finish handle VPC Prefix List for "{service_name}"')

        # Create or Update the appropriate resource for each service range found
        ### WAF IPSet
        logging.info('Handling WAF IPSet')
        waf_ipsets_by_scope: Dict[str, Dict] = {}
        for config_service in config_services['Services']:
            service_name = config_service['Name']

            logging.info(f'Start handle WAF IPSet for "{service_name}"')
            if service_name not in service_ranges:
                logging.warning(f'Service name "{service_name}" not found in service ranges variable. This condition should NEVER happens. Possible bug in the code. Please investigate.')
            else:
                # Handle WAF IPSet
                if 'WafIPSet' not in config_service:
                    logging.info(f'Service "{service_name}" not configured with "WafIPSet"')
                else:
                    if not config_service['WafIPSet']['Enable']:
                        logging.info(f'Service "{service_name}" is configured with "WafIPSet" but it is not enable')
                    else:
                        # Scope can be 'CLOUDFRONT' or 'REGIONAL'
                        for ipset_scope in config_service['WafIPSet']['Scopes']:
                            logging.info(f'Service "{service_name}" WAF Scope "{ipset_scope}"')
                            try:
                                waf_ipsets: Dict[str, Dict] = {}
                                # Will list WAF IPSets only once for each scope
                                if ipset_scope in waf_ipsets_by_scope:
                                    waf_ipsets = waf_ipsets_by_scope[ipset_scope]
                                else:
                                    logging.info(f'Will get the list of WAF IPSets for the first time for scope "{ipset_scope}"')
                                    waf_ipsets = list_waf_ipset(waf_client, ipset_scope)
                                    waf_ipsets_by_scope[ipset_scope] = waf_ipsets

                                should_summarize = config_service['WafIPSet']['Summarize']
                                ipset_names: Dict[str, list[str]] = manage_waf_ipset(waf_client, waf_ipsets, service_name, ipset_scope, service_ranges, should_summarize)
                                resource_names['WafIPSet']['created'] += ipset_names['created']
                                resource_names['WafIPSet']['updated'] += ipset_names['updated']
                            except Exception as error:
                                logging.error("Error handling WAF IPSet. It will not block the execution. It will continue to other services and resources.")
                                logging.exception(error)
            logging.info(f'Finish handle WAF IPSet for "{service_name}"')

    except Exception as error:
        logging.exception(error)
        raise error

    logging.debug(f'Function return: {resource_names}')
    logging.info('lambda_handler end')
    return resource_names

### General functions
def get_ip_groups_json(url: str, expected_hash: str) -> str:
    """Get ip-range.json file and check if it mach the expected MD5 hash"""
    logging.info('get_ip_groups_json start')
    logging.debug(f'Parameter url: {url}')
    logging.debug(f'Parameter expected_hash: {expected_hash}')

    # Get ip-ranges.json file
    logging.info(f'Updating from "{url}"')
    if not url.lower().startswith('http'):
        raise Exception(f'Expecting an HTTP protocol URL, got "{url}"')
    req = request.Request(url)
    with request.urlopen(req) as response: #nosec B310
        ip_json = response.read()
    logging.info(f'Got "ip-ranges.json" file from "{url}"')
    logging.debug(f'File content: {ip_json}')

    # Calculate MD5 hash from current file
    m = hashlib.md5() # nosec B303
    m.update(ip_json)
    current_hash = m.hexdigest()
    logging.debug(f'Calculated MD5 file hash "{current_hash}"')

    # If the hash provided is 'test-hash', returns the JSON without checking the hash
    if expected_hash == 'test-hash':
        logging.info('Running in test mode')
        return ip_json

    # Current file hash MUST match the one expected
    if current_hash != expected_hash:
        raise Exception(f'MD5 Mismatch: got "{current_hash}" expected "{expected_hash}"')

    logging.debug(f'Function return: {ip_json}')
    logging.info('get_ip_groups_json end')
    return ip_json

def get_ranges_for_service(ranges: Dict, config_services: Dict) -> Dict[str, ServiceIPRange]:
    """Gets IPv4 and IPv6 prefixes from the matching services"""
    logging.info('get_ranges_for_service start')
    logging.debug(f'Parameter ranges: {ranges}')
    logging.debug(f'Parameter config_services: {config_services}')

    service_ranges: Dict[str, ServiceIPRange] = {}
    service_control: Dict[str, bool] = {}
    for config_service in config_services['Services']:
        service_name = config_service['Name']
        if len(config_service['Regions']) > 0:
            for region in config_service['Regions']:
                logging.info(f"Will search for '{service_name}' and region '{region}'")
                key = f"{service_name}-{region}"

                service_control[key] = True
                service_ranges[service_name] = ServiceIPRange()
        else:
            logging.info(f"Will search for '{service_name}' without consider a region, so will get all prefixes from all regions")
            key = f"{service_name}"

            service_control[key] = True
            service_ranges[service_name] = ServiceIPRange()

    # Loop over the IPv4 prefixes and appends the matching services
    logging.info('Searching for IPv4 prefixes')
    for prefix in ranges['prefixes']:
        service_name = prefix['service']
        service_region = prefix['region']
        key = f"{service_name}-{service_region}"
        if key in service_control:
            logging.info(f"Found service: '{service_name}' region: '{service_region}' range: {prefix['ip_prefix']}")
            service_ranges[service_name].ipv4.ip_list.append(prefix['ip_prefix'])
        else:
            key = f"{service_name}"
            if key in service_control:
                logging.info(f"Found service: '{service_name}' range: {prefix['ip_prefix']}")
                service_ranges[service_name].ipv4.ip_list.append(prefix['ip_prefix'])

    # Loop over the IPv6 prefixes and appends the matching services
    logging.info('Searching for IPv6 prefixes')
    for ipv6_prefix in ranges['ipv6_prefixes']:
        service_name = ipv6_prefix['service']
        service_region = ipv6_prefix['region']
        key = f"{service_name}-{service_region}"
        if key in service_control:
            logging.info(f"Found service: '{service_name}' region: '{service_region}' range: {ipv6_prefix['ipv6_prefix']}")
            service_ranges[service_name].ipv6.ip_list.append(ipv6_prefix['ipv6_prefix'])
        else:
            key = f"{service_name}"
            if key in service_control:
                logging.info(f"Found service: '{service_name}' range: {ipv6_prefix['ipv6_prefix']}")
                service_ranges[service_name].ipv6.ip_list.append(ipv6_prefix['ipv6_prefix'])

    # Sort all ranges
    for service_name in service_ranges.keys():
        service_ranges[service_name].ipv4.sort()
        service_ranges[service_name].ipv6.sort()

    logging.debug(f'Function return: {service_ranges}')
    logging.info('get_ranges_for_service end')
    return service_ranges

### WAF IPSet functions
def manage_waf_ipset(client: Any, waf_ipsets: Dict[str, Dict], service_name: str, ipset_scope: str, service_ranges: Dict[str, ServiceIPRange], should_summarize: bool) -> Dict[str, list[str]]:
    """Create or Update WAF IPSet"""
    logging.info('manage_waf_ipset start')
    logging.debug(f'Parameter client: {client}')
    logging.debug(f'Parameter waf_ipsets: {waf_ipsets}')
    logging.debug(f'Parameter service_name: {service_name}')
    logging.debug(f'Parameter ipset_scope: {ipset_scope}')
    logging.debug(f'Parameter service_ranges: {service_ranges}')
    logging.debug(f'Parameter should_summarize: {should_summarize}')

    # Dictionary to return the IPSet names that will be created or updated
    ipset_names: Dict[str, list[str]] = {'created': [], 'updated': []}

    for ip_version in ['ipv4', 'ipv6']:
        if not service_ranges[service_name].asdict()[ip_version].ip_list:
            logging.debug(f'No IP ranges found for service "{service_name}" and IP version "{ip_version}"')
        else:
            # Found ranges for specific IP version (ipv4 or ipv6)
            address_list: list[str] = service_ranges[service_name].asdict()[ip_version].ip_list
            logging.debug(f'Summarize: "{should_summarize}" and address list lenght: "{len(address_list)}"')
            if should_summarize and (len(address_list) > 1):
                address_list = service_ranges[service_name].asdict()[ip_version].summarized()

            # Check if it is to create or update WAF IPSet
            ipset_name: str = f"aws-ip-ranges-{service_name.lower().replace('_', '-')}-{ip_version}"
            if ipset_name in waf_ipsets:
                # IPSets exists, so will update it
                logging.debug(f'WAF IPSet "{ipset_name}" found. Will update it.')
                update_waf_ipset(client, ipset_name, ipset_scope, waf_ipsets[ipset_name], address_list)
                ipset_names['updated'].append(ipset_name)
            else:
                # IPSet not found, so will create it
                # IPAddressVersion can be 'IPV4' or 'IPV6'
                logging.debug(f'WAF IPSet "{ipset_name}" not found. Will create it.')
                create_waf_ipset(client, ipset_name, ipset_scope, ip_version.upper(), address_list)
                ipset_names['created'].append(ipset_name)

    logging.debug(f'Function return: {ipset_names}')
    logging.info('manage_waf_ipset end')
    return ipset_names

def create_waf_ipset(client: Any, ipset_name: str, ipset_scope: str, ipset_version: str, address_list: list[str]) -> None:
    """Create the AWS WAF IP set"""
    logging.info('create_waf_ipset start')
    logging.debug(f'Parameter client: {client}')
    logging.debug(f'Parameter ipset_name: {ipset_name}')
    logging.debug(f'Parameter ipset_scope: {ipset_scope}')
    logging.debug(f'Parameter ipset_version: {ipset_version}')
    logging.debug(f'Parameter address_list: {address_list}')

    logging.info(f'Creating IPSet "{ipset_name}" with scope "{ipset_scope}" with {len(address_list)} CIDRs. List: {address_list}')
    response = client.create_ip_set(
        Name=ipset_name,
        Scope=ipset_scope,
        Description=DESCRIPTION,
        IPAddressVersion=ipset_version,
        Addresses=address_list,
        Tags=[
            {
                'Key': 'Name',
                'Value': ipset_name
            },
            {
                'Key': 'ManagedBy',
                'Value': 'update-aws-ip-ranges'
            },
            {
                'Key': 'CreatedAt',
                'Value': datetime.now(timezone.utc).isoformat()
            },
            {
                'Key': 'UpdatedAt',
                'Value': 'Not yet'
            },
        ]
    )
    logging.info(f'Created IPSet "{ipset_name}"')
    logging.debug(f'Response: {response}')
    logging.debug('Function return: None')
    logging.info('create_waf_ipset end')

def update_waf_ipset(client: Any, ipset_name: str, ipset_scope: str, waf_ipset: Dict[str, Any], address_list: list[str]) -> None:
    """Updates the AWS WAF IP set"""
    logging.info('update_waf_ipset start')
    logging.debug(f'Parameter client: {client}')
    logging.debug(f'Parameter ipset_name: {ipset_name}')
    logging.debug(f'Parameter ipset_scope: {ipset_scope}')
    logging.debug(f'Parameter waf_ipset: {waf_ipset}')
    logging.debug(f'Parameter address_list: {address_list}')

    ipset_id: str = waf_ipset['Id']
    ipset_lock_token: str = waf_ipset['LockToken']
    ipset_description: str = waf_ipset['Description']
    ipset_arn: str = waf_ipset['ARN']
    logging.debug(f'ipset_id: {ipset_id}')
    logging.debug(f'ipset_lock_token: {ipset_lock_token}')
    logging.debug(f'ipset_description: {ipset_description}')
    logging.debug(f'ipset_arn: {ipset_arn}')

    # Update IPSet
    logging.info(f'Updating IPSet "{ipset_name}" with scope "{ipset_scope}" with lock_token "{ipset_lock_token}" with {len(address_list)} CIDRs. List: {address_list}')
    response = client.update_ip_set(
        Name=ipset_name,
        Scope=ipset_scope,
        Id=ipset_id,
        Description=ipset_description,
        Addresses=address_list,
        LockToken=ipset_lock_token
    )
    logging.info(f'Updated IPSet "{ipset_name}"')
    logging.debug(f'Response: {response}')

    # Update IPSet tags
    logging.info(f'Updating Tags for "{ipset_name}" with ARN "{ipset_arn}"')
    response = client.tag_resource(
        ResourceARN=ipset_arn,
        Tags=[{'Key': 'UpdatedAt','Value': datetime.now(timezone.utc).isoformat()}]
    )
    logging.info(f'Updated Tags for "{ipset_name}" with ARN {ipset_arn}')
    logging.debug(f'Response: {response}')
    logging.debug('Function return: None')
    logging.info('update_waf_ipset end')

def list_waf_ipset(client: Any, ipset_scope: str) -> Dict[str, Dict]:
    """List all AWS WAF IP set from specific scope"""
    logging.info('list_waf_ipset start')
    logging.debug(f'Parameter client: {client}')
    logging.debug(f'Parameter ipset_scope: {ipset_scope}')

    response = client.list_ip_sets(Scope=ipset_scope)
    logging.info(f'Listed IPSet with scope "{ipset_scope}"')
    logging.debug(f'Response: {response}')

    # Put all IPSets inside a dictionary
    ipsets: Dict[str, Dict] = {ipset['Name']:ipset for ipset in response['IPSets']}
    logging.debug(f'Function return: {ipsets}')
    logging.info('list_waf_ipset end')
    return ipsets


### VPC Prefix List
def manage_prefix_list(client: Any, vpc_prefix_lists: Dict[str, Dict], service_name: str, service_ranges: Dict[str, ServiceIPRange], should_summarize: bool) -> Dict[str, list[str]]:
    """Create or Update VPC Prefix List"""
    logging.info('manage_prefix_list start')
    logging.debug(f'Parameter client: {client}')
    logging.debug(f'Parameter vpc_prefix_lists: {vpc_prefix_lists}')
    logging.debug(f'Parameter service_name: {service_name}')
    logging.debug(f'Parameter service_ranges: {service_ranges}')
    logging.debug(f'Parameter should_summarize: {should_summarize}')

    # Dictionary to return the Prefix List names that will be created or updated
    prefix_list_names: Dict[str, list[str]] = {'created': [], 'updated': []}

    for ip_version in ['ipv4', 'ipv6']:
        if not service_ranges[service_name].asdict()[ip_version].ip_list:
            logging.debug(f'No IP ranges found for service "{service_name}" and IP version "{ip_version}"')
        else:
            # Found ranges for specific IP version (ipv4 or ipv6)
            address_list: list[str] = service_ranges[service_name].asdict()[ip_version].ip_list
            logging.debug(f'Summarize: "{should_summarize}" and address list lenght: "{len(address_list)}"')
            if should_summarize and (len(address_list) > 1):
                address_list = service_ranges[service_name].asdict()[ip_version].summarized()

            prefix_list_name: str = f"aws-ip-ranges-{service_name.lower().replace('_', '-')}-{ip_version}"
            if prefix_list_name in vpc_prefix_lists:
                # Prefix List exists, so will update it
                logging.debug(f'VPC Prefix List "{prefix_list_name}" found. Will update it.')
                updated = update_prefix_list(client, prefix_list_name, vpc_prefix_lists[prefix_list_name], address_list)
                if updated:
                    prefix_list_names['updated'].append(prefix_list_name)
            else:
                # Prefix List not found, so will create it
                logging.debug(f'VPC Prefix List "{prefix_list_name}" not found. Will create it.')
                create_prefix_list(client, prefix_list_name, ip_version.upper(), address_list)
                prefix_list_names['created'].append(prefix_list_name)

    logging.debug(f'Function return: {prefix_list_names}')
    logging.info('manage_prefix_list end')
    return prefix_list_names

def list_prefix_lists(client: Any) -> Dict[str, Dict]:
    """List all VPC Prefix List"""
    logging.info('list_prefix_lists start')
    logging.debug(f'Parameter client: {client}')

    response = client.describe_managed_prefix_lists()
    logging.info('Listed VPC Prefix Lists')
    logging.debug(f'Response: {response}')

    # Put all VPC Prefix Lists inside a dictionary
    prefix_lists: Dict[str, Dict] = {prefix_list['PrefixListName']:prefix_list for prefix_list in response['PrefixLists']}
    logging.debug(f'Function return: {prefix_lists}')
    logging.info('list_prefix_lists end')
    return prefix_lists

def get_prefix_list_by_id(client: Any, prefix_list_id: str) -> Dict[str, Any]:
    """Get VPC Prefix List by ID"""
    logging.info('get_prefix_list_by_id start')
    logging.debug(f'Parameter client: {client}')
    logging.debug(f'Parameter prefix_list_id: {prefix_list_id}')

    response = client.describe_managed_prefix_lists(PrefixListIds=[prefix_list_id])
    logging.info(f'Got VPC Prefix Lists with ID: {prefix_list_id}')
    logging.debug(f'Response: {response}')

    prefix_list: Dict[str, Any] = response['PrefixLists'][0]
    logging.debug(f'Function return: {prefix_list}')
    logging.info('get_prefix_list_by_id end')
    return prefix_list

def create_prefix_list(client: Any, prefix_list_name: str, prefix_list_ip_version: str, address_list: list[str]) -> None:
    """Create the VPC Prefix List"""
    logging.info('create_prefix_list start')
    logging.debug(f'Parameter client: {client}')
    logging.debug(f'Parameter prefix_list_name: {prefix_list_name}')
    logging.debug(f'Parameter prefix_list_ip_version: {prefix_list_ip_version}')
    logging.debug(f'Parameter address_list: {address_list}')

    # Create the list of Prefix List entries to create
    prefix_list_entries: list[Dict] = []
    for addr in address_list:
        prefix_list_entries.append(
            {
                'Cidr': addr,
                'Description': DESCRIPTION
            }
        )
    logging.debug(f'Prefix List entries: {prefix_list_entries}')

    # Add 10 enties extra when create Prefix List for future expansion
    max_entries: int = len(prefix_list_entries) + 10

    logging.info(f'Creating VPC Prefix List "{prefix_list_name}" with max entries "{max_entries}" with address family "{prefix_list_ip_version}" with {len(address_list)} CIDRs. List: {address_list}')
    response = client.create_managed_prefix_list(
        PrefixListName=prefix_list_name,
        Entries=prefix_list_entries,
        MaxEntries=max_entries,
        TagSpecifications=[
            {
                'ResourceType': 'prefix-list',
                'Tags': [
                    {
                        'Key': 'Name',
                        'Value': prefix_list_name
                    },
                    {
                        'Key': 'ManagedBy',
                        'Value': 'update-aws-ip-ranges'
                    },
                    {
                        'Key': 'CreatedAt',
                        'Value': datetime.now(timezone.utc).isoformat()
                    },
                    {
                        'Key': 'UpdatedAt',
                        'Value': 'Not yet'
                    },
                ]
            },
        ],
        AddressFamily=prefix_list_ip_version
    )
    logging.info(f'Created VPC Prefix List "{prefix_list_name}"')
    logging.debug(f'Response: {response}')
    logging.debug('Function return: None')
    logging.info('create_prefix_list end')

def update_prefix_list(client: Any, prefix_list_name: str, prefix_list: Dict[str, Any], address_list: list[str]) -> bool:
    """Updates the AWS VPC Prefix List"""
    logging.info('update_prefix_list start')
    logging.debug(f'Parameter client: {client}')
    logging.debug(f'Parameter prefix_list_name: {prefix_list_name}')
    logging.debug(f'Parameter prefix_list: {prefix_list}')
    logging.debug(f'Parameter address_list: {address_list}')

    prefix_list_id: str = prefix_list['PrefixListId']
    prefix_list_max_entries: int = prefix_list['MaxEntries']
    prefix_list_version: int = prefix_list['Version']
    logging.debug(f'prefix_list_id: {prefix_list_id}')
    logging.debug(f'prefix_list_max_entries: {prefix_list_max_entries}')
    logging.debug(f'prefix_list_version: {prefix_list_version}')

    # Get current Prefix List entries
    current_entries: Dict[str, str] = get_prefix_list_entries(client, prefix_list_name, prefix_list_id, prefix_list_version)
    # Filter to get the list of entries to remove from Prefix List
    entries_to_remove: list[Dict] = [{'Cidr': cidr} for cidr in current_entries.keys() if cidr not in address_list]
    # Filter to get the list of entries to add into Prefix List
    entries_to_add: list[Dict] = [{'Cidr': cidr, 'Description': DESCRIPTION} for cidr in address_list if cidr not in current_entries]
    logging.debug(f'current_entries: {current_entries}')
    logging.debug(f'entries_to_remove: {entries_to_remove}')
    logging.debug(f'entries_to_add: {entries_to_add}')

    updated: bool = False
    if (not entries_to_add) and (not entries_to_remove):
        logging.info(f'Nothing to add or remove at "{prefix_list_name}"')
    else:
        # Only change max entries if there is entries to add and current max entries is less than len of new address list
        if entries_to_add:
            logging.debug('Exist entries to add')
            if prefix_list_max_entries < len(address_list):
                logging.debug(f'Current Prefix List max entries "{prefix_list_max_entries}" is lower than new range length "{len(address_list)}", so will change it to increase')
                # Update Prefix List to change max entries first
                # You cannot modify the entries of a prefix list and modify the size of a prefix list at the same time.
                prefix_list_max_entries = len(address_list)
                logging.debug(f'New max entries value "{prefix_list_max_entries}"')

                logging.info(f'Updating VPC Prefix List "{prefix_list_name}" with id "{prefix_list_id}" with max entries "{prefix_list_max_entries}" with version "{prefix_list_version}"')
                response = client.modify_managed_prefix_list(
                    PrefixListId=prefix_list_id,
                    PrefixListName=prefix_list_name,
                    MaxEntries=prefix_list_max_entries
                )
                logging.info(f'Updated VPC Prefix List "{prefix_list_name}"')
                logging.debug(f'Response: {response}')

                prefix_list_version = response['PrefixList']['Version']
                current_state: str = response['PrefixList']['State']
                current_state_message: str = response['PrefixList']['StateMessage']
                logging.debug(f'prefix_list_version: {prefix_list_version}')
                logging.debug(f'current_state: {current_state}')
                logging.debug(f'current_state_message: {current_state_message}')

                if current_state not in ['modify-in-progress', 'modify-complete', 'modify-failed']:
                    raise Exception(f'Error updating VPC Prefix List max entries. Invalid state. Expecting "modify-in-progress" or "modify-complete" or "modify-failed". Got "{current_state}". Name: "{prefix_list_name}" ID: "{prefix_list_id}" current version: "{prefix_list_version}" new max entries: "{prefix_list_max_entries}" StateMessage: "{current_state_message}"')
                if current_state == 'modify-failed':
                    raise Exception(f'Error updating VPC Prefix List max entries. State is "modify-failed". Name: "{prefix_list_name}" ID: "{prefix_list_id}" current version: "{prefix_list_version}" new max entries: "{prefix_list_max_entries}" StateMessage: "{current_state_message}"')
                if current_state == 'modify-in-progress':
                    logging.info('Updating VPC Prefix List max entries is in progress. Will wait.')
                    for count in range(5):
                        seconds_to_wait: int = count + (count + 1)
                        logging.info(f'Waiting {seconds_to_wait} seconds')
                        time.sleep(seconds_to_wait)
                        wait_prefix_list: Dict[str, Any] = get_prefix_list_by_id(client, prefix_list_id)
                        if wait_prefix_list['State'] == 'modify-complete':
                            break
                    else:
                        # Else doesn't execute if exit via break
                        raise Exception("Error updating VPC Prefix List max entries. Can't wait anymore.")

        # Update Prefix List entries
        logging.info(f'Updating VPC Prefix List "{prefix_list_name}" with id "{prefix_list_id}" with version "{prefix_list_version}" with {len(address_list)} CIDRs.')
        logging.info(f'Updating VPC Prefix List "{prefix_list_name}" Entries to add: {entries_to_add}')
        logging.info(f'Updating VPC Prefix List "{prefix_list_name}" Entries to remove: {entries_to_remove}')
        logging.info(f'Updating VPC Prefix List "{prefix_list_name}" Full list of entries: {address_list}')
        response = client.modify_managed_prefix_list(
            PrefixListId=prefix_list_id,
            CurrentVersion=prefix_list_version,
            PrefixListName=prefix_list_name,
            AddEntries=entries_to_add,
            RemoveEntries=entries_to_remove
        )
        updated = True
        logging.info(f'Updated VPC Prefix List "{prefix_list_name}"')
        logging.debug(f'Response: {response}')

        # Update VPC Prefix List tags
        logging.info(f'Updating Tags for "{prefix_list_name}" with ID "{prefix_list_id}"')
        # Adds or overwrites only the specified tags for the specified Amazon EC2 resource or resources.
        response = client.create_tags(
            Resources=[prefix_list_id],
            Tags=[{'Key': 'UpdatedAt', 'Value': datetime.now(timezone.utc).isoformat()}]
        )
        logging.info(f'Updated Tags for "{prefix_list_name}" with ID {prefix_list_id}')
        logging.debug(f'Response: {response}')

    logging.debug(f'Function return: {updated}')
    logging.info('update_prefix_list end')
    return updated

def get_prefix_list_entries(client: Any, prefix_list_name: str, prefix_list_id: str, prefix_list_version: int) -> Dict[str, str]:
    """Get the AWS VPC Prefix List entries"""
    logging.info('get_prefix_list_entries start')
    logging.debug(f'Parameter client: {client}')
    logging.debug(f'Parameter prefix_list_name: {prefix_list_name}')
    logging.debug(f'Parameter prefix_list_id: {prefix_list_id}')
    logging.debug(f'Parameter prefix_list_version: {prefix_list_version}')

    logging.info(f'Getting VPC Prefix List entries "{prefix_list_name}" with id "{prefix_list_id}" with version "{prefix_list_version}"')
    response = client.get_managed_prefix_list_entries(
        PrefixListId=prefix_list_id,
        TargetVersion=prefix_list_version
    )
    logging.info(f'Got VPC Prefix List entries "{prefix_list_name}"')
    logging.debug(f'Response: {response}')

    # Add entries in a dictionary
    entries: Dict[str, str] = {}
    for entrie in response['Entries']:
        if 'Description' in entrie:
            entries[entrie['Cidr']] = entrie['Description']
        else:
            entries[entrie['Cidr']] = ''
    logging.debug(f'Function return: {entries}')
    logging.info('get_prefix_list_entries end')
    return entries


# if __name__ == '__main__':
#     with open('test_event.json', 'r') as event_file:
#         event: Dict[str, Any] = json.loads(event_file.read())
#         lambda_handler(event, None)
