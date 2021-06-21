"""
This script does the following:

1. Downloads a small repository of known bad stuff (14 bad things) and
    saves to temporary directory. The ransomware folder from the
    https://github.com/Endermanch/MalwareDatabase/ repo.
2. Unzips the samples into the correct directory for the environment
   (malware_rl/envs/utils/samples).
3. Renames each sample to its corresponding SHA256 hash.
4. Removes temporary malware directory
"""

import argparse
import glob
import gzip
import hashlib
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile

# Third Part Libraries
import svn.remote

MODULE_PATH = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]
UTIL_PATH = os.path.join(MODULE_PATH, "malware_rl/envs/utils/")
SAMPLE_PATH = os.path.join(MODULE_PATH, "malware_rl/envs/utils/samples/")
ZIP_PASSWORD = "mysubsarethebest"
DEFAULT_MALWARE_REPOS = [
    "https://github.com/Endermanch/MalwareDatabase/trunk/ransomwares",
    "https://github.com/Endermanch/MalwareDatabase/trunk/rogues",
    "https://github.com/Endermanch/MalwareDatabase/trunk/trojans",
    "https://github.com/Endermanch/MalwareDatabase/trunk/jokes",
]
TEMP_SAMPLE_PATHS = ["ransomwares/", "rogues/", "trojans/", "jokes/"]
BENIGN_REPO = "https://github.com/xournalpp/xournalpp/releases/download/1.0.18/xournalpp-1.0.18-windows.zip"
EMBER_MODEL_PATH = "https://raw.githubusercontent.com/Azure/2020-machine-learning-security-evasion-competition/master/defender/defender/models/ember_model.txt.gz"


def retrive_url(source_file_url=None, filename=None):
    """
    Retrieves a file
    """
    if os.path.exists(filename):
        print(f"[-] {filename} already present. Skipping")
    else:
        urllib.request.urlretrieve(source_file_url, filename)


def download_specific_github_file(
    source_file_url=None,
    filename=None,
    storage_directory=None,
):
    """
    Downloads a specific file from a github repo.
    If gzipped, decompresses and drops into directory
    """
    retrive_url(source_file_url, filename)
    shutil.move(
        os.path.join(os.getcwd(), filename),
        os.path.join(storage_directory, filename),
    )

    if os.path.join(storage_directory, filename).endswith(".gz"):
        split_filename = os.path.splitext(filename)[0]

        with gzip.open(os.path.join(UTIL_PATH, filename), "r") as f_in, open(
            os.path.join(UTIL_PATH, split_filename),
            "wb",
        ) as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(os.path.join(UTIL_PATH, filename))
    print("[+] Success - Ember Model downloaded")


def download_specific_git_repo_directory(temp_path=None, source_repo=None):
    """
    Downloads a specific directory within a git repo.
    """
    if os.path.exists(temp_path) is False:
        repo = svn.remote.RemoteClient(source_repo)

        try:
            repo.checkout(source_repo)
            print(
                "[+] Success - Samples Downloaded " "Placed into Temp Directory",
            )

        except svn.exception.SvnException:
            print(
                """
            Subversion not found. In order to download the sample malware,
            Subversion (svn) needs to be installed. This provides a method of
            downloading only the target folder rather than the whole repo.
            """
            )


def unzip_file(filename=None, source_zip=None, password=False):
    """
    Unzips a .zip file
    """
    try:
        if password:
            with zipfile.ZipFile(filename, "r") as file:
                file.extractall(
                    source_zip,
                    pwd=bytes(ZIP_PASSWORD, "utf-8"),
                )
        else:
            with zipfile.ZipFile(filename, "r") as file:
                file.extractall(source_zip)
    except:
        pass


def unzip_samples(temp_sample_path=None, sample_path=None):
    """
    Unzips all .zip's within the target directory
    """
    if os.path.exists(temp_sample_path):
        target_path_contents = glob.glob(
            os.path.join(
                os.getcwd(),
                temp_sample_path + "*.zip",
            ),
        )
        for filename in target_path_contents:
            unzip_file(filename, sample_path, password=True)

    print("[+] Success - Samples Unzipped")


def rename_samples_to_sha256_hash(sample_path=None):
    """
    Renames all malware files within a target directory to there
    SHA256 hash
    """
    for files in glob.glob(os.path.join(sample_path, "*")):
        sha256_hash = hashlib.sha256()
        with open(files, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                sha256_hash.update(byte_block)
            computed_hash = sha256_hash.hexdigest()
            os.rename(files, os.path.join(sample_path, computed_hash))
    print("[+] Success - Samples renamed to their SHA256 hash")


def clean_up_temp_samples_dir(directory_to_remove=None):
    """
    Clean up temporary samples directory
    """
    if os.path.exists(directory_to_remove):
        shutil.rmtree(directory_to_remove)
        print(f"[+] Cleanup Complete - {directory_to_remove} has been removed")


def check_if_samples_exist(directory_to_check=None):
    """
    Checks if samples directory contains samples
    """
    if len(os.listdir(directory_to_check)) == 0:
        return True
    else:
        return False


def generate_example_benign_strings_output(benign_repo=None, output_dir=None):
    """
    Downloads a sample open source windows application and
    generates strings output
    """
    output_zip = benign_repo.split("/")[-1]
    output_filename = "".join(output_zip.split(".")[:-1])

    retrive_url(benign_repo, output_zip)
    unzip_file(output_zip)
    os.remove(output_zip)

    file = open(
        "./malware_rl/envs/controls/good_strings/xournal-strings.txt",
        "w",
    )
    unzipped_filename = glob.glob("xournalpp-*")[0]
    subprocess.run(["strings", unzipped_filename], stdout=file)
    shutil.move(
        os.path.join(MODULE_PATH, unzipped_filename),
        os.path.join(
            MODULE_PATH,
            "malware_rl/envs/controls/trusted/" + unzipped_filename,
        ),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A small utility that helps with the downloading of the requirements for the malware-rl environment",
    )
    parser.add_argument(
        "--accept",
        help="accept liability for downloading bad things",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--force",
        help="forces the download even if samples directory is" "not empty",
        action="store_true",
    )
    parser.add_argument(
        "--clean",
        help="deletes the contents of the samples directory",
        action="store_true",
    )
    parser.add_argument(
        "--strings",
        help="download goodware windows executable and generate text file containing strings output",
        action="store_true",
    )
    args = parser.parse_args()

    if args.clean:
        for sample in glob.glob(os.path.join(SAMPLE_PATH, "*")):
            os.remove(sample)

    if args.strings:
        generate_example_benign_strings_output(
            benign_repo=BENIGN_REPO,
            output_dir=MODULE_PATH,
        )

    if args.accept:
        if check_if_samples_exist(directory_to_check=SAMPLE_PATH) | args.force is True:
            for temp_sample_path, malware_repo in zip(
                TEMP_SAMPLE_PATHS,
                DEFAULT_MALWARE_REPOS,
            ):
                print(
                    f"[*] Attempting to Download {temp_sample_path} Samples & Place in Temp Directory",
                )
                download_specific_git_repo_directory(
                    temp_path=temp_sample_path,
                    source_repo=malware_repo,
                )
                print("[*] Attempting to Unzip Samples")
                unzip_samples(
                    temp_sample_path=temp_sample_path,
                    sample_path=SAMPLE_PATH,
                )
                print("[*] Attempting to Rename Files to SHA256 Hash")
                rename_samples_to_sha256_hash(sample_path=SAMPLE_PATH)
                print("[*] Attempting Clean Up")
                clean_up_temp_samples_dir(directory_to_remove=temp_sample_path)

            print("[*] Attempting downloading Ember Model")
            download_specific_github_file(
                source_file_url=EMBER_MODEL_PATH,
                filename="ember_model.txt.gz",
                storage_directory=UTIL_PATH,
            )
            print("[+] Success - Ember Model Downloaded")
            print("[*] Attempting to generate example benign strings output")
            generate_example_benign_strings_output(
                benign_repo=BENIGN_REPO,
                output_dir=MODULE_PATH,
            )
            print("[+] Success - Example Strings Output Generated")

        else:
            print(
                "[-] It looks like there is something in your samples "
                "directory (malware_rl/envs/utils/samples) already, aborting"
                "download. Use the --force flag to continue download",
            )
