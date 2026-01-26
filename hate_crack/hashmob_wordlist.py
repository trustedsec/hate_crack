import json
import os
import requests


def sanitize_filename(filename):
    """Sanitize a filename by replacing spaces and removing problematic characters."""
    import re

    filename = filename.replace(' ', '_')
    filename = re.sub(r'[^A-Za-z0-9._-]', '', filename)
    return filename


def get_api_key():
    """Return hashmob_api_key from config.json in package or project root."""
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(pkg_dir, os.pardir))
    for cfg in (os.path.join(pkg_dir, 'config.json'), os.path.join(project_root, 'config.json')):
        if os.path.isfile(cfg):
            try:
                with open(cfg) as f:
                    config = json.load(f)
                    key = config.get('hashmob_api_key')
                    if key:
                        return key
            except Exception:
                continue
    return None


def get_hcat_wordlists_dir():
    """Return the configured `hcatWordlists` directory from config.json.

    Checks both the package directory and the project root for config.json.
    Falls back to project_root/wordlists when not configured.
    """
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(pkg_dir, os.pardir))
    candidates = [
        os.path.join(pkg_dir, 'config.json'),
        os.path.join(project_root, 'config.json')
    ]
    default = os.path.join(project_root, 'wordlists')
    for config_path in candidates:
        try:
            if os.path.isfile(config_path):
                with open(config_path) as f:
                    config = json.load(f)
                    path = config.get('hcatWordlists')
                    if path:
                        path = os.path.expanduser(path)
                        if not os.path.isabs(path):
                            path = os.path.join(project_root, path)
                        os.makedirs(path, exist_ok=True)
                        return path
        except Exception:
            continue
    os.makedirs(default, exist_ok=True)
    return default


def download_hashmob_wordlist_list():
    """Fetch available wordlists from Hashmob API v2 and print them."""
    url = "https://hashmob.net/api/v2/resource"
    api_key = get_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        wordlists = [r for r in data if r.get('type') == 'wordlist']
        print("Available Hashmob Wordlists:")
        for idx, wl in enumerate(wordlists):
            print(f"{idx+1}. {wl.get('name', wl.get('file_name', ''))} - {wl.get('information', '')}")
        return wordlists
    except Exception as e:
        print(f"Error fetching Hashmob wordlists: {e}")
        return []


def download_hashmob_wordlist(file_name, out_path):
    """Download a wordlist file from Hashmob by file name."""
    url = f"https://hashmob.net/api/v2/downloads/research/wordlists/{file_name}"
    api_key = get_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        with requests.get(url, headers=headers, stream=True, timeout=60, allow_redirects=True) as r:
            if r.status_code in (301, 302, 303, 307, 308):
                redirect_url = r.headers.get('Location')
                if redirect_url:
                    print(f"Following redirect to: {redirect_url}")
                    return download_hashmob_wordlist(redirect_url, out_path)
                print("Redirect with no Location header!")
                return False
            r.raise_for_status()
            content_type = r.headers.get('Content-Type', '')
            if 'text/plain' in content_type:
                html = r.content.decode(errors='replace')
                import re
                match = re.search(
                    r"<meta[^>]+http-equiv=['\"]refresh['\"][^>]+content=['\"]0;url=([^'\"]+)['\"]",
                    html,
                    re.IGNORECASE
                )
                if match:
                    real_url = match.group(1)
                    print(f"Found meta refresh redirect to: {real_url}")
                    with requests.get(real_url, stream=True, timeout=120) as r2:
                        r2.raise_for_status()
                        with open(out_path, 'wb') as f:
                            for chunk in r2.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                    print(f"Downloaded {out_path}")
                    return True
                print("Error: Received HTML instead of file. Possible permission or quota issue.")
                return False
            with open(out_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        print(f"Downloaded {out_path}")
        return True
    except Exception as e:
        print(f"Error downloading wordlist: {e}")
        return False


def list_official_wordlists():
    """List files in the official wordlists directory via the Hashmob API."""
    url = "https://hashmob.net/api/v2/downloads/research/official/"
    api_key = get_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        try:
            data = resp.json()
            print("Official Hashmob Wordlists (JSON):")
            for idx, entry in enumerate(data):
                print(f"{idx+1}. {entry}")
            return data
        except Exception:
            print("Official Hashmob Wordlists (raw text):")
            print(resp.text)
            return resp.text
    except Exception as e:
        print(f"Error listing official wordlists: {e}")
        return []


def list_and_download_official_wordlists():
    """List files in the official wordlists directory via the Hashmob API, prompt for selection, and download."""
    url = "https://hashmob.net/api/v2/downloads/research/official/"
    api_key = get_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            print("Unexpected response format. Raw output:")
            print(data)
            return
        print("Official Hashmob Wordlists:")
        for idx, entry in enumerate(data):
            name = entry.get('name', entry.get('file_name', str(entry)))
            file_name = entry.get('file_name', name)
            info = entry.get('information', '')
            print(f"{idx+1}. {name} ({file_name}) - {info}")
        print("a. Download ALL files")
        sel = input("Enter the number of the wordlist to download, or 'a' for all, or 'q' to quit: ")
        if sel.lower() == 'q':
            return
        if sel.lower() == 'a':
            for entry in data:
                file_name = entry.get('file_name')
                if not file_name:
                    print("No file_name found for an entry, skipping.")
                    continue
                out_path = entry.get('name', file_name)
                if download_official_wordlist(file_name, out_path):
                    dest_dir = get_hcat_wordlists_dir()
                    archive_path = os.path.join(dest_dir, out_path) if not os.path.isabs(out_path) else out_path
                    if archive_path.endswith('.7z'):
                        extract_with_7z(archive_path)
            return
        try:
            idx = int(sel) - 1
            if idx < 0 or idx >= len(data):
                print("Invalid selection.")
                return
            file_name = data[idx].get('file_name')
            if not file_name:
                print("No file_name found for selection.")
                return
            out_path = data[idx].get('name', file_name)
            if download_official_wordlist(file_name, out_path):
                dest_dir = get_hcat_wordlists_dir()
                archive_path = os.path.join(dest_dir, out_path) if not os.path.isabs(out_path) else out_path
                if archive_path.endswith('.7z'):
                    extract_with_7z(archive_path)
        except Exception as e:
            print(f"Error: {e}")
    except Exception as e:
        print(f"Error listing official wordlists: {e}")


def download_official_wordlist(file_name, out_path):
    """Download a file from the official wordlists directory with a progress bar."""
    import sys

    url = f"https://hashmob.net/api/v2/downloads/research/official/{file_name}"
    api_key = get_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        with requests.get(url, headers=headers, stream=True, timeout=120) as r:
            r.raise_for_status()
            try:
                total = int(r.headers.get('content-length') or 0)
            except Exception:
                total = 0
            downloaded = 0
            chunk_size = 8192
            out_path = sanitize_filename(out_path)
            dest_dir = get_hcat_wordlists_dir()
            archive_path = os.path.join(dest_dir, out_path) if not os.path.isabs(out_path) else out_path
            os.makedirs(os.path.dirname(archive_path), exist_ok=True)
            with open(archive_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            done = int(50 * downloaded / total)
                            percent = 100 * downloaded / total
                            bar = '=' * done + ' ' * (50 - done)
                            sys.stdout.write(
                                f"\r[{bar}] {percent:6.2f}% ({downloaded // 1024} KB/{total // 1024} KB)"
                            )
                            sys.stdout.flush()
                        else:
                            sys.stdout.write(f"\rDownloaded {downloaded // 1024} KB")
                            sys.stdout.flush()
            sys.stdout.write("\n")
        print(f"Downloaded {archive_path}")
        if archive_path.endswith('.7z'):
            extract_with_7z(archive_path)
        return True
    except Exception as e:
        print(f"Error downloading official wordlist: {e}")
        return False


def extract_with_7z(archive_path, output_dir=None):
    """Extract a .7z archive using the 7z or 7za command."""
    import shutil
    import subprocess

    if output_dir is None:
        output_dir = os.path.splitext(archive_path)[0]
    os.makedirs(output_dir, exist_ok=True)
    sevenz_bin = shutil.which('7z') or shutil.which('7za')
    if not sevenz_bin:
        print("[!] 7z or 7za not found in PATH. Please install p7zip-full or 7-zip to extract archives.")
        return False
    try:
        print(f"Extracting {archive_path} to {output_dir} ...")
        result = subprocess.run(
            [sevenz_bin, 'x', '-y', archive_path, f'-o{output_dir}'],
            capture_output=True,
            text=True
        )
        print(result.stdout)
        if result.returncode == 0:
            print(f"[+] Extraction complete: {archive_path}")
            return True
        print(f"[!] Extraction failed for {archive_path}: {result.stderr}")
        return False
    except Exception as e:
        print(f"[!] Error extracting {archive_path}: {e}")
        return False
