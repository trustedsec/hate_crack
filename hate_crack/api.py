import json
import os
from typing import Callable, Tuple

from hate_crack.hashview import HashviewAPI
from hate_crack.hashmob_wordlist import list_and_download_official_wordlists


def download_hashes_from_hashview(
    hashview_url: str,
    hashview_api_key: str,
    debug_mode: bool,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[..., None] = print,
) -> Tuple[str, str]:
    """Interactive Hashview download flow used by CLI."""
    api_harness = HashviewAPI(hashview_url, hashview_api_key, debug=debug_mode)
    result = api_harness.list_customers()
    if 'customers' in result and result['customers']:
        api_harness.display_customers_multicolumn(result['customers'])
    customer_id = int(input_fn("\nEnter customer ID: "))
    try:
        customer_hashfiles = api_harness.get_customer_hashfiles(customer_id)
        if customer_hashfiles:
            print_fn("\n" + "=" * 100)
            print_fn(f"Hashfiles for Customer ID {customer_id}:")
            print_fn("=" * 100)
            print_fn(f"{'ID':<10} {'Name':<88}")
            print_fn("-" * 100)
            for hf in customer_hashfiles:
                hf_id = hf.get('id', 'N/A')
                hf_name = hf.get('name', 'N/A')
                if len(str(hf_name)) > 88:
                    hf_name = str(hf_name)[:85] + "..."
                print_fn(f"{hf_id:<10} {hf_name:<88}")
            print_fn("=" * 100)
            print_fn(f"Total: {len(customer_hashfiles)} hashfile(s)")
        else:
            print_fn(f"\nNo hashfiles found for customer ID {customer_id}")
    except Exception as exc:
        print_fn(f"\nWarning: Could not list hashfiles: {exc}")
        print_fn("You may need to manually find the hashfile ID in the web interface.")
    hashfile_id = int(input_fn("\nEnter hashfile ID: "))
    hcat_hash_type = "1000"
    output_file = f"left_{customer_id}_{hashfile_id}.txt"
    download_result = api_harness.download_left_hashes(customer_id, hashfile_id, output_file)
    print_fn(f"\n✓ Success: Downloaded {download_result['size']} bytes")
    print_fn(f"  File: {download_result['output_file']}")
    hcat_hash_file = download_result['output_file']
    print_fn("\nNow starting hate_crack with:")
    print_fn(f"  Hash file: {hcat_hash_file}")
    print_fn(f"  Hash type: {hcat_hash_type}")
    return hcat_hash_file, hcat_hash_type


def download_hashmob_wordlists(print_fn=print) -> None:
    """Download official Hashmob wordlists."""
    list_and_download_official_wordlists()
    print_fn("Hashmob wordlist download complete.")


def download_weakpass_torrent(download_torrent, filename: str, print_fn=print) -> None:
    """Download a single Weakpass torrent file by name or URL."""
    print_fn(f"[i] Downloading: {filename}")
    download_torrent(filename)


def download_all_weakpass_torrents(
    fetch_all_wordlists,
    download_torrent,
    print_fn=print,
    cache_path: str = "weakpass_wordlists.json",
) -> None:
    """Download all Weakpass torrents from a cached wordlist JSON."""
    if not os.path.exists(cache_path):
        print_fn("[i] weakpass_wordlists.json not found, fetching wordlist cache...")
        fetch_all_wordlists()
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            all_wordlists = json.load(f)
    except Exception as exc:
        print_fn(f"Failed to load local wordlist cache: {exc}")
        raise
    torrents = [wl['torrent_url'] for wl in all_wordlists if wl.get('torrent_url')]
    print_fn(f"[i] Downloading {len(torrents)} torrents...")
    for tfile in torrents:
        print_fn(f"[i] Downloading: {tfile}")
        download_torrent(tfile)
    print_fn("[i] All torrents processed.")
