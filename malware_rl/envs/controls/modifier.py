import array
import json
import os
import random
import subprocess
import sys
import tempfile
from os import listdir
from os.path import isfile, join

import lief

module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]

COMMON_SECTION_NAMES = (
    open(
        os.path.join(
            module_path,
            "section_names.txt",
        ),
    )
    .read()
    .rstrip()
    .split("\n")
)
COMMON_IMPORTS = json.load(
    open(os.path.join(module_path, "small_dll_imports.json")),
)


class ModifyBinary:
    def __init__(self, bytez):
        self.bytez = bytez
        self.trusted_path = module_path + "/trusted/"
        self.good_str_path = module_path + "/good_strings/"

    def _randomly_select_trusted_file(self):
        return random.choice(
            [
                join(self.trusted_path, f)
                for f in listdir(self.trusted_path)
                if (f != ".gitkeep") and (isfile(join(self.trusted_path, f)))
            ],
        )

    def _randomly_select_good_strings(self):
        good_strings = random.choice(
            [
                join(self.good_str_path, f)
                for f in listdir(self.good_str_path)
                if (f != ".gitkeep") and (isfile(join(self.good_str_path, f)))
            ],
        )

        with open(good_strings) as f:
            strings = f.read()

        return strings

    def _random_length(self):
        return 2 ** random.randint(5, 8)

    def _search_cave(
        self,
        name,
        body,
        file_offset,
        vaddr,
        cave_size=128,
        _bytes=b"\x00",
    ):
        found_caves = []
        null_count = 0
        size = len(body)

        for offset in range(size):
            byte = body[offset]
            check = False

            if byte in _bytes:
                null_count += 1
            else:
                check = True

            if offset == size - 1:
                check = True
                offset += 1

            if check:
                if null_count >= cave_size:
                    cave_start = file_offset + offset - null_count
                    cave_end = file_offset + offset
                    cave_size = null_count
                    found_caves.append([cave_start, cave_end, cave_size])
                null_count = 0
        return found_caves

    def _binary_to_bytez(self, binary, imports=False):
        # Write modified binary to disk
        builder = lief.PE.Builder(binary)
        builder.build_imports(imports)
        builder.build()

        self.bytez = array.array("B", builder.get_build()).tobytes()
        return self.bytez

    def rename_section(self):
        binary = lief.PE.parse(list(self.bytez))
        targeted_section = random.choice(binary.sections)
        targeted_section.name = random.choice(COMMON_SECTION_NAMES)[:5]

        self.bytez = self._binary_to_bytez(binary)
        return self.bytez

    def add_bytes_to_section_cave(self):
        caves = []
        binary = lief.PE.parse(list(self.bytez))
        base_addr = binary.optional_header.imagebase
        for section in binary.sections:
            section_offset = section.pointerto_raw_data
            vaddr = section.virtual_address + base_addr
            body = bytearray(section.content)

            if section.sizeof_raw_data > section.virtual_size:
                body.extend(
                    list(b"\x00" * (section.sizeof_raw_data - section.virtual_size)),
                )

            caves.extend(
                self._search_cave(
                    section.name,
                    body,
                    section_offset,
                    vaddr,
                ),
            )

        if caves:
            random_selected_cave = random.choice(caves)
            upper = random.randrange(256)
            add_bytes = bytearray(
                random.randint(0, upper) for _ in range(random_selected_cave[-1])
            )
            self.bytez = (
                self.bytez[: random_selected_cave[0]]
                + add_bytes
                + self.bytez[random_selected_cave[1] :]
            )

        return self.bytez

    def modify_machine_type(self):
        binary = lief.PE.parse(list(self.bytez))
        binary.header.machine = random.choice(
            [
                lief.PE.MACHINE_TYPES.AMD64,
                lief.PE.MACHINE_TYPES.IA64,
                lief.PE.MACHINE_TYPES.ARM64,
                lief.PE.MACHINE_TYPES.POWERPC,
            ],
        )

        self.bytez = self._binary_to_bytez(binary)

        return self.bytez

    def modify_timestamp(self):
        binary = lief.PE.parse(list(self.bytez))
        binary.header.time_date_stamps = random.choice(
            [
                0,
                868967292,
                993636360,
                587902357,
                872078556,
            ],
        )

        self.bytez = self._binary_to_bytez(binary)

        return self.bytez

    def pad_overlay(self):
        byte_pattern = random.choice([i for i in range(256)])
        overlay = bytearray([byte_pattern] * 100000)
        self.bytez += overlay

        return self.bytez

    def append_benign_data_overlay(self):
        random_benign_file = self._randomly_select_trusted_file()
        benign_binary = lief.PE.parse(random_benign_file)
        benign_binary_section_content = benign_binary.get_section(
            ".text",
        ).content
        overlay = bytearray(benign_binary_section_content)
        self.bytez += overlay

        return self.bytez

    def append_benign_binary_overlay(self):
        random_benign_file = self._randomly_select_trusted_file()

        with open(random_benign_file, "rb") as f:
            benign_binary = f.read()
        self.bytez += benign_binary

        return self.bytez

    def add_section_benign_data(self):
        random_benign_file = self._randomly_select_trusted_file()
        benign_binary = lief.PE.parse(random_benign_file)
        benign_binary_section_content = benign_binary.get_section(
            ".text",
        ).content

        binary = lief.PE.parse(list(self.bytez))

        current_section_names = [section.name for section in binary.sections]
        available_section_names = list(
            set(COMMON_SECTION_NAMES) - set(current_section_names),
        )
        section = lief.PE.Section(random.choice(available_section_names))
        section.content = benign_binary_section_content
        binary.add_section(section, lief.PE.SECTION_TYPES.DATA)

        self.bytez = self._binary_to_bytez(binary)
        return self.bytez

    def add_section_strings(self):
        good_strings = self._randomly_select_good_strings()
        binary = lief.PE.parse(list(self.bytez))

        current_section_names = [section.name for section in binary.sections]
        available_section_names = list(
            set(COMMON_SECTION_NAMES) - set(current_section_names),
        )
        section = lief.PE.Section(random.choice(available_section_names))
        section.content = [ord(c) for c in good_strings]
        binary.add_section(section, lief.PE.SECTION_TYPES.DATA)

        self.bytez = self._binary_to_bytez(binary)
        return self.bytez

    def add_strings_to_overlay(self):
        """
        Open a txt file of strings from low scoring binaries.
        https://skylightcyber.com/2019/07/18/cylance-i-kill-you/
        """
        good_strings = self._randomly_select_good_strings()
        self.bytez += bytes(good_strings, encoding="ascii")

        return self.bytez

    def add_imports(self):
        binary = lief.PE.parse(list(self.bytez))

        # draw a library at random
        libname = random.choice(list(COMMON_IMPORTS.keys()))
        funcname = random.choice(list(COMMON_IMPORTS[libname]))
        lowerlibname = libname.lower()

        # find this lib in the imports, if it exists
        lib = None
        for im in binary.imports:
            if im.name.lower() == lowerlibname:
                lib = im
                break

        if lib is None:
            # add a new library
            lib = binary.add_library(libname)

        # get current names
        names = {e.name for e in lib.entries}
        if funcname not in names:
            lib.add_entry(funcname)

        self.bytez = self._binary_to_bytez(binary, imports=True)

        return self.bytez

    def remove_debug(self):
        binary = lief.PE.parse(list(self.bytez))

        if binary.has_debug:
            for i, e in enumerate(binary.data_directories):
                if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
                    e.rva = 0
                    e.size = 0
                    self.bytez = self._binary_to_bytez(binary)
                    return self.bytez
        # no debug found
        return self.bytez

    def modify_optional_header(self):
        binary = lief.PE.parse(list(self.bytez))

        oh = {
            "major_linker_version": [2, 6, 7, 9, 11, 14],
            "minor_linker_version": [0, 16, 20, 22, 25],
            "major_operating_system_version": [4, 5, 6, 10],
            "minor_operating_system_version": [0, 1, 3],
            "major_image_version": [0, 1, 5, 6, 10],
            "minor_image_version": [0, 1, 3],
        }

        key = random.choice(list(oh.keys()))

        modified_val = random.choice(oh[key])
        binary.optional_header.__setattr__(key, modified_val)

        self.bytez = self._binary_to_bytez(binary)
        return self.bytez

    def break_optional_header_checksum(self):
        binary = lief.PE.parse(list(self.bytez))
        binary.optional_header.checksum = 0
        self.bytez = self._binary_to_bytez(binary)
        return self.bytez

    def upx_unpack(self):
        # dump bytez to a temporary file
        tmpfilename = os.path.join(
            tempfile._get_default_tempdir(),
            next(tempfile._get_candidate_names()),
        )

        with open(tmpfilename, "wb") as outfile:
            outfile.write(self.bytez)

        with open(os.devnull, "w") as DEVNULL:
            retcode = subprocess.call(
                ["upx", tmpfilename, "-d", "-o", tmpfilename + "_unpacked"],
                stdout=DEVNULL,
                stderr=DEVNULL,
            )

        os.unlink(tmpfilename)

        if retcode == 0:  # sucessfully unpacked
            with open(tmpfilename + "_unpacked", "rb") as result:
                self.bytez = result.read()

            os.unlink(tmpfilename + "_unpacked")

        return self.bytez

    def upx_pack(self):
        # tested with UPX 3.94
        # WARNING: upx compression only works on binaries over 100KB
        tmpfilename = os.path.join(
            tempfile._get_default_tempdir(),
            next(tempfile._get_candidate_names()),
        )

        # dump bytez to a temporary file
        with open(tmpfilename, "wb") as outfile:
            outfile.write(self.bytez)

        options = ["--force", "--overlay=copy"]
        compression_level = random.randint(1, 9)
        options += [f"-{compression_level}"]
        options += [f"--compress-exports={random.randint(0, 1)}"]
        options += [f"--compress-icons={random.randint(0, 3)}"]
        options += [f"--compress-resources={random.randint(0, 1)}"]
        options += [f"--strip-relocs={random.randint(0, 1)}"]

        with open(os.devnull, "w") as DEVNULL:
            retcode = subprocess.call(
                ["upx"] + options + [tmpfilename, "-o", tmpfilename + "_packed"],
                stdout=DEVNULL,
                stderr=DEVNULL,
            )

        os.unlink(tmpfilename)

        if retcode == 0:  # successfully packed

            with open(tmpfilename + "_packed", "rb") as infile:
                self.bytez = infile.read()

            os.unlink(tmpfilename + "_packed")

        return self.bytez


def modify_sample(bytez, action):
    bytez = ModifyBinary(bytez).__getattribute__(action)()
    return bytez


ACTION_TABLE = {
    "modify_machine_type": "modify_machine_type",
    "pad_overlay": "pad_overlay",
    "append_benign_data_overlay": "append_benign_data_overlay",
    "append_benign_binary_overlay": "append_benign_binary_overlay",
    "add_bytes_to_section_cave": "add_bytes_to_section_cave",
    "add_section_strings": "add_section_strings",
    "add_section_benign_data": "add_section_benign_data",
    "add_strings_to_overlay": "add_strings_to_overlay",
    "add_imports": "add_imports",
    "rename_section": "rename_section",
    "remove_debug": "remove_debug",
    "modify_optional_header": "modify_optional_header",
    "modify_timestamp": "modify_timestamp",
    "break_optional_header_checksum": "break_optional_header_checksum",
    "upx_unpack": "upx_unpack",
    "upx_pack": "upx_pack",
}

if __name__ == "__main__":
    # use for testing/debugging actions
    import hashlib

    from IPython import embed

    # filename =  '../utils/samples/e090668cfbbe44474cc979f09c1efe82a644a351c5b1a2e16009be273118e053' # upx packed sample
    filename = "../utils/samples/7a5d1bb166c07ed101f2ee9cb43b3a8ce0d90d52788a0d9791a040d2cdcc8057"
    with open(filename, "rb") as f:
        bytez = f.read()

    m = hashlib.sha256()
    m.update(bytez)
    print(f"original hash: {m.hexdigest()}")

    action = "upx_pack"
    bytez = modify_sample(bytez, action)

    m = hashlib.sha256()
    m.update(bytez)
    print(f"modified hash: {m.hexdigest()}")

    embed()
