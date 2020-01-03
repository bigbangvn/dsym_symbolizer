"""
Prerequisites:
$ pip install biplist
$ pip install requests

Usage:
python dsym_symbolizer.py --dsym_url https://www.example.com/MyStuff.framework.dSYM.zip \
                          --source_path /Users/MeMySelfAndI/MyStuffSources \
                          --binary_path /Users/MeMySelfAndI/MyProject/Pods/MyStuff/MyStuff.framework
"""

import argparse
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
import tempfile
import urlparse
from os import path

import requests
import biplist

def main():
    parser = argparse.ArgumentParser(description="Downloads dSYM into ~/dsyms/, overwrites if exists.\n"
                                                 "And points it to the specified source folder,\n"
                                                 " then when you debug code that uses a "
                                                 "binary that relates to the given dSYM,\n"
                                                 "you'll be able to see its source code.")

    parser.add_argument("--binary_path",
                        required=True,
                        help="Path to binary of which sources you wish to see.")

    parser.add_argument("--dsym_url",
                        required=True,
                        help="URL to the dSYM (tar.bz2 / zip).")

    parser.add_argument("--source_path",
                        required=True,
                        help="Path to the source code of the binary you wish to debug.")

    args = parser.parse_args()

    source_path_to_map = try_find_source_path_to_map(args.binary_path, args.source_path)

    dsym_path = download_dsym(args.dsym_url)

    binary_uuids = get_uuids_of_dwarf(args.binary_path)
    dsym_uuids = get_uuids_of_dwarf(dsym_path)

    verify_uuids(binary_uuids, dsym_uuids)

    generate_plist_for_dsym(dsym_path, args.binary_path, args.source_path, source_path_to_map, binary_uuids)


def normalize_binary_path(binary_path):
    """
    If a path to a framework is given, it'll return the full path to the dwarf binary.

    :type binary_path: string
    :return: string
    """
    if binary_path.lower().endswith(".framework"):
        biplist_dict = biplist.readPlist(path.join(binary_path, "Info.plist"))
        binary_path = path.join(binary_path, biplist_dict["CFBundleExecutable"])
    elif binary_path.lower().endswith(".dsym"):
        dwarf_path = path.join(binary_path, "Contents", "Resources", "DWARF")
        dwarf_files = os.listdir(dwarf_path)
        assert len(dwarf_files) == 1, "Found more than one dwarf file in dsym: %s, unexpected, failing miserably." \
                                      % repr(dwarf_files)
        binary_path = path.join(dwarf_path, dwarf_files[0])

    return binary_path


def get_uuids_of_dwarf(binary_path):

    """
    :type binary_path: string - can be a framework or a valid dwarf binary, FAT or thin.
    :return: a dictionary of arch -> uuid :dict
    """
    binary_path = normalize_binary_path(binary_path)

    proc = subprocess.Popen(["dwarfdump", "--uuid", binary_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdoutdata, stderrdata) = proc.communicate()
    lines = stdoutdata.split("\n")
    archs_to_uuids = {}

    #
    # An output line of the dwarfdump tool looks like this:
    # "UUID: E29B1FB0-EBFE-3740-BF5F-5B65CE884713 (x86_64) /path/to/binary"
    #
    for line in lines:
        elements = line.split(" ")
        if len(elements) >= 4:
            archs_to_uuids[elements[2].replace("(", "").replace(")", "")] = elements[1]

    assert len(archs_to_uuids) > 0, "Unable to obtain UUIDs from %s, stdout: %s, stderr: %s" \
                                    % (binary_path, stdoutdata, stderrdata)

    return archs_to_uuids


def try_find_source_path_to_map(binary_path, source_path):
    """

    :type binary_path: string - can be a framework or a valid dwarf binary, FAT or thin.
    :type source_path: string
    """
    binary_path = normalize_binary_path(binary_path)

    proc = subprocess.Popen('nm -pa "%s" | grep "SO /"' % binary_path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdoutputdata, stderrdata) = proc.communicate()

    lines = stdoutputdata.split("\n")

    for line in lines:
        split_result = re.split(r"\s+", line)
        # A line looks like this
        # 0000000000000000 - 00 0000    SO /potential/path/in/remote/machine
        if len(split_result) >= 5:
            potential_original_path = split_result[5]
            potential_original_path_fragments = potential_original_path.split("/")

            potential_path_suffix = ""

            #
            # Here's an example of how the algorithm below works:
            #
            # let's assume that source_path             == /my/path
            #                   potential_original_path == /remote/place/foo/bar/baz
            #
            # Then we attempt to see if /my/path/baz exists, if not then /my/path/bar/baz, and then
            # /my/path/foo/bar/baz and if it does we return /remote/place/
            #
            for i in reversed(xrange(len(potential_original_path_fragments))):
                if potential_original_path_fragments[i] != "":
                    potential_path_suffix = path.join(potential_original_path_fragments[i], potential_path_suffix)

                    if path.isdir(path.join(source_path, potential_path_suffix)):
                        return potential_original_path[0:potential_original_path.index(potential_path_suffix)-1]

    assert False, "Unable to find path match, sorry :-( failing miserably!"


#

def download_dsym(dsym_url):
    split_result = urlparse.urlsplit(dsym_url)

    assert split_result is not None, "Invalid URL"

    file_name = split_result.path.split("/")[-1]

    assert file_name != "", "File name not found in URL"

    temp_path = path.join(tempfile.mkdtemp(), file_name)

    # From http://stackoverflow.com/a/15645088/1067624
    with open(temp_path, "wb") as f:
        print "Downloading %s" % file_name
        response = requests.get(dsym_url, stream=True)
        total_length = response.headers.get('content-length')

        if total_length is None:  # no content length header
            f.write(response.content)
        else:
            dl = 0
            total_length = int(total_length)
            for data in response.iter_content(chunk_size=4096):
                dl += len(data)
                f.write(data)
                done = int(50 * dl / total_length)
                sys.stdout.write("\r[%s%s]" % ('=' * done, ' ' * (50-done)))
                sys.stdout.flush()

    dsym_path = None

    def prepare_dsym_path(file_name):

        dsym_path = path.join(os.environ["HOME"], "dsyms", file_name)
        if path.isdir(dsym_path):
            shutil.rmtree(dsym_path)

        os.makedirs(dsym_path)

        return dsym_path

    if temp_path.lower().endswith("zip"):
        with zipfile.ZipFile(temp_path) as z:
            for archived_file in z.filelist:
                if archived_file.filename.lower().endswith(".dsym/"):
                    dsym_path = prepare_dsym_path(archived_file.filename)
                    break

            z.extractall(path.dirname(path.dirname(dsym_path)))

    if temp_path.lower().endswith("tar.bz2"):
        with tarfile.open(temp_path, "r:bz2") as tf:
            for archived_file in tf:
                if archived_file.name.lower().endswith(".dsym"):
                    dsym_path = prepare_dsym_path(archived_file.name)
                    break

            tf.extractall(path.dirname(dsym_path))

    assert dsym_path is not None, "Failed preparing dSYM file path, failing."

    return dsym_path


def generate_plist_for_dsym(dsym_path, binary_path, source_path, source_path_to_map, binary_uuids):

    """

    :param binary_uuids: dict<string. string> of arch -> uuid
    :param source_path_to_map: string
    :param source_path: string
    :param binary_path: string
    :param dsym_path: string
    """
    for arch in binary_uuids:
        plist_dict = {"DBGArchitecture": arch,
                      "DBGBuildSourcePath": source_path_to_map,
                      "DBGSourcePath": source_path,
                      "DBGDSYMPath": normalize_binary_path(dsym_path),
                      "DBGSymbolRichExecutable": normalize_binary_path(binary_path)}

        plistlib.writePlist(plist_dict, path.join(dsym_path, "Contents", "Resources", binary_uuids[arch] + ".plist"))


def verify_uuids(binary_uuids, dsym_uuids):
    for arch in binary_uuids:
        if arch not in dsym_uuids:
            assert False, "Unable to find %s architecture in dSYM" % arch
        elif binary_uuids[arch] != dsym_uuids[arch]:
            assert False, "uuid mismatch for arch %s, binary uuid=%s, dsym uuid=%s" % (arch, binary_uuids[arch], dsym_uuids[arch])


main()
