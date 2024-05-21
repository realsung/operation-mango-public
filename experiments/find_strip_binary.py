#!/usr/bin/env python3
# python .\symSearch.py ./firmware_SaTC
# pip install pyelftools
import os
import argparse
from elftools.elf.elffile import ELFFile

border_binary = ['boa', 'httpd', '.cgi', 'lighttpd', 'uhttpd', 'mini_httpd', 'goahead', 'prog.cgi', 'tdhttpd', 'onvifd', 'cgibin', 'setup.cgi', 'mwareserver', 'centaurus', 'rc', 'system.so']

count_stripped = 0
count_notstripped = 0

def is_elf(file_path):
    try:
        with open(file_path, 'rb') as file:
            return file.read(4) == b'\x7fELF'
    except Exception as e:
        return False

def is_stripped(file_path):
    global count_stripped, count_notstripped
    with open(file_path, 'rb') as file:
        elf = ELFFile(file)
        symtab = elf.get_section_by_name('.symtab')
        if symtab is None: count_stripped += 1
        else: count_notstripped += 1

        return symtab is None

def scan_directory(directory):
    elf_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if is_elf(file_path):
                # 웹 서버 함수에 대해서만 찾기
                for border in border_binary:
                    if border == file:
                        stripped = is_stripped(file_path)
                        elf_files.append((file_path, stripped))

                # 모든 바이너리 대상으로 찾기
                # stripped = is_stripped(file_path)
                # elf_files.append((file_path, stripped))
    return elf_files

def main():
    parser = argparse.ArgumentParser(description="Scan directory for ELF files and check if they are stripped")
    parser.add_argument("directory", type=str, help="The directory to scan")
    args = parser.parse_args()

    elf_files = scan_directory(args.directory)
    for file_path, stripped in elf_files:
        status = "stripped" if stripped else "not stripped"
        print(f"{file_path}: {status}")
    print(f"[+] strip count {count_stripped}")
    print(f'[-] not strip count : {count_notstripped}')

if __name__ == "__main__":
    main()
