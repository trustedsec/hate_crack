#!/usr/bin/env python3

import sys
import os
import subprocess
import shutil
import pathlib


def usage():
    print(f"usage: python {sys.argv[0]} <input file list> <output directory>")


def main():
    try:
        if not os.path.isfile(sys.argv[1]):
            print(f"{sys.argv[1]} is not a valid file.")
            sys.exit(1)
        if not os.path.isdir(sys.argv[2]):
            create_directory = input(
                f"{sys.argv[2]} is not a directory. Do you want to create it? (Y or N) "
            )
            if create_directory.upper() == "Y":
                try:
                    pathlib.Path(sys.argv[2]).mkdir(parents=True, exist_ok=True)
                except PermissionError:
                    print(
                        "You do not have the correct permissions to create the directory. "
                        "Please try a different path or create manually."
                    )
                    sys.exit(1)
            else:
                print("Please specify a valid directory and try again.")
                sys.exit(1)
        input_list = open(sys.argv[1], "r")
        destination = sys.argv[2]
    except IndexError:
        usage()
        sys.exit(1)

    # Resolve binary paths relative to script location
    script_dir = os.path.dirname(os.path.realpath(__file__))
    ext = ".app" if sys.platform == "darwin" else ".bin"
    splitlen_bin = os.path.join(script_dir, "hashcat-utils", "bin", f"splitlen{ext}")
    rli_bin = os.path.join(script_dir, "hashcat-utils", "bin", f"rli{ext}")

    # Verify binaries exist
    for binary_path, binary_name in [
        (splitlen_bin, "splitlen"),
        (rli_bin, "rli"),
    ]:
        if not os.path.isfile(binary_path):
            print(
                f"Error: {binary_name} binary not found at {binary_path}. "
                "Ensure hashcat-utils is built."
            )
            sys.exit(1)

    # Get list of wordlists from <input file list> argument
    for wordlist in input_list:
        wordlist = wordlist.strip()
        if not wordlist:
            continue
        print(wordlist)

        # Parse wordlists by password length into "optimized" <output directory>
        if len(os.listdir(destination)) == 0:
            with open(wordlist, "r") as wl:
                try:
                    subprocess.run(
                        [splitlen_bin, destination],
                        stdin=wl,
                        check=True,
                        capture_output=True,
                    )
                except subprocess.CalledProcessError as e:
                    print(f"Error running splitlen on {wordlist}: {e.stderr.decode()}")
                    sys.exit(1)
        else:
            if not os.path.isdir("/tmp/splitlen"):
                os.mkdir("/tmp/splitlen")
            with open(wordlist, "r") as wl:
                try:
                    subprocess.run(
                        [splitlen_bin, "/tmp/splitlen"],
                        stdin=wl,
                        check=True,
                        capture_output=True,
                    )
                except subprocess.CalledProcessError as e:
                    print(f"Error running splitlen on {wordlist}: {e.stderr.decode()}")
                    sys.exit(1)

            # Copy unique passwords into "optimized" <output directory>
            for file in os.listdir("/tmp/splitlen"):
                src_file = os.path.join("/tmp/splitlen", file)
                dst_file = os.path.join(destination, file)
                if not os.path.isfile(dst_file):
                    shutil.copyfile(src_file, dst_file)
                else:
                    try:
                        subprocess.run(
                            [rli_bin, src_file, "/tmp/splitlen.out", dst_file],
                            check=True,
                            capture_output=True,
                        )
                    except subprocess.CalledProcessError as e:
                        print(f"Error running rli on {file}: {e.stderr.decode()}")
                        sys.exit(1)
                    if os.path.getsize("/tmp/splitlen.out") > 0:
                        with open(dst_file, "a") as dst:
                            with open("/tmp/splitlen.out", "r") as src:
                                dst.write(src.read())

        # Clean Up
        if os.path.isdir("/tmp/splitlen"):
            shutil.rmtree("/tmp/splitlen")
        if os.path.isfile("/tmp/splitlen.out"):
            os.remove("/tmp/splitlen.out")


if __name__ == "__main__":
    main()
