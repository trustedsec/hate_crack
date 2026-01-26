"""
hashview_api.py
Modularized Hashview API integration (class only).
"""


import os
import json
import requests




# Hashview Integration - Real API implementation matching hate_crack.py
class HashviewAPI:
	"""Hashview API integration for uploading/downloading hashfiles, wordlists, jobs, and customers."""

	FILE_FORMATS = {
		'pwdump': 0,
		'netntlm': 1,
		'kerberos': 2,
		'shadow': 3,
		'user:hash': 4,
		'hash_only': 5,
	}

	def __init__(self, base_url, api_key, debug=False):
		self.base_url = base_url.rstrip('/')
		self.api_key = api_key
		self.debug = debug
		self.session = requests.Session()
		self.session.cookies.set('uuid', api_key)
		self.session.verify = False
		import urllib3
		urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

	def list_customers(self):
		url = f"{self.base_url}/v1/customers"
		resp = self.session.get(url)
		resp.raise_for_status()
		data = resp.json()
		if 'users' in data:
			customers = json.loads(data['users'])
			return {'customers': customers}
		return data

	def list_hashfiles(self):
		url = f"{self.base_url}/v1/hashfiles"
		resp = self.session.get(url)
		resp.raise_for_status()
		data = resp.json()
		if 'hashfiles' in data:
			if isinstance(data['hashfiles'], str):
				hashfiles = json.loads(data['hashfiles'])
			else:
				hashfiles = data['hashfiles']
			return hashfiles
		return []

	def get_customer_hashfiles(self, customer_id):
		all_hashfiles = self.list_hashfiles()
		return [hf for hf in all_hashfiles if int(hf.get('customer_id', 0)) == customer_id]

	def display_customers_multicolumn(self, customers):
		if not customers:
			print("\nNo customers found.")
			return
		try:
			terminal_width = os.get_terminal_size().columns
		except:
			terminal_width = 120
		max_id_len = max(len(str(c.get('id', ''))) for c in customers)
		col_width = max_id_len + 2 + 30 + 2
		num_cols = max(1, terminal_width // col_width)
		print("\n" + "="*terminal_width)
		print("Available Customers:")
		print("="*terminal_width)
		num_customers = len(customers)
		rows = (num_customers + num_cols - 1) // num_cols
		for row in range(rows):
			line_parts = []
			for col in range(num_cols):
				idx = row + col * rows
				if idx < num_customers:
					customer = customers[idx]
					cust_id = customer.get('id', 'N/A')
					cust_name = customer.get('name', 'N/A')
					name_width = col_width - max_id_len - 2 - 2
					if len(str(cust_name)) > name_width:
						cust_name = str(cust_name)[:name_width-3] + "..."
					entry = f"{cust_id}: {cust_name}"
					line_parts.append(entry.ljust(col_width))
			print("".join(line_parts).rstrip())
		print("="*terminal_width)
		print(f"Total: {len(customers)} customer(s)")

	def upload_hashfile(self, file_path, customer_id, hash_type, file_format=5, hashfile_name=None):
		if hashfile_name is None:
			hashfile_name = os.path.basename(file_path)
		with open(file_path, 'rb') as f:
			file_content = f.read()
		url = (
			f"{self.base_url}/v1/hashfiles/upload/"
			f"{customer_id}/{file_format}/{hash_type}/{hashfile_name}"
		)
		headers = {'Content-Type': 'text/plain'}
		resp = self.session.post(url, data=file_content, headers=headers)
		resp.raise_for_status()
		return resp.json()

	def create_job(self, name, hashfile_id, customer_id, limit_recovered=False, notify_email=True):
		url = f"{self.base_url}/v1/jobs/add"
		headers = {'Content-Type': 'application/json'}
		data = {
			"name": name,
			"hashfile_id": hashfile_id,
			"customer_id": customer_id,
		}
		resp = self.session.post(url, json=data, headers=headers)
		resp.raise_for_status()
		return resp.json()

	def download_left_hashes(self, customer_id, hashfile_id, output_file=None):
		url = f"{self.base_url}/v1/hashfiles/{hashfile_id}"
		resp = self.session.get(url)
		resp.raise_for_status()
		if output_file is None:
			output_file = f"left_{customer_id}_{hashfile_id}.txt"
		with open(output_file, 'wb') as f:
			f.write(resp.content)
		return {'output_file': output_file, 'size': len(resp.content)}

	def upload_cracked_hashes(self, file_path, hash_type='1000'):
		valid_lines = []
		with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
			for line in f:
				line = line.strip()
				if '31d6cfe0d16ae931b73c59d7e0c089c0' in line:
					continue
				if not line or ':' not in line:
					continue
				parts = line.split(':', 1)
				if len(parts) != 2:
					break
				hash_value = parts[0].strip()
				plaintext = parts[1].strip()
				valid_lines.append(f"{hash_value}:{plaintext}")
		converted_content = '\n'.join(valid_lines)
		url = f"{self.base_url}/v1/hashes/import/{hash_type}"
		headers = {'Content-Type': 'text/plain'}
		resp = self.session.post(url, data=converted_content, headers=headers)
		resp.raise_for_status()
		try:
			json_response = resp.json()
			if 'type' in json_response and json_response['type'] == 'Error':
				raise Exception(f"Hashview API Error: {json_response.get('msg', 'Unknown error')}")
			return json_response
		except (json.JSONDecodeError, ValueError):
			raise Exception(f"Invalid API response: {resp.text[:200]}")

	def create_customer(self, name):
		url = f"{self.base_url}/v1/customers/add"
		headers = {'Content-Type': 'application/json'}
		data = {"name": name}
		resp = self.session.post(url, json=data, headers=headers)
		resp.raise_for_status()
		return resp.json()

