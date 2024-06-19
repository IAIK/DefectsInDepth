#!/usr/bin/env python3

import argparse
import csv
import json
import os
import subprocess
import re
import numpy as np

parser = argparse.ArgumentParser(
    prog="evaluate.py",
    description="Evaluates the kernel source folders")

parser.add_argument(
    "filename_config",
    help="filename to the config.json file")
args = parser.parse_args()

filename_config = args.filename_config
config = {}
with open(filename_config, "r") as f:
    config = json.loads(f.read())
if config == {}:
    print("filename config error")
    exit(-1)

VERSION_TO_MITIGATIONS = {
    "kernel-3.10": [
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_STRICT_KERNEL_RWX",
    ],
    "kernel-3.18": [
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_STRICT_KERNEL_RWX",
        "CONFIG_ARM64_UAO",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_UNMAP_KERNEL_AT_EL0",
    ],
    "kernel-4.4": [
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_STRICT_KERNEL_RWX",
        "CONFIG_ARM64_UAO",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_UNMAP_KERNEL_AT_EL0",
    ],
    "kernel-4.9": [
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_STRICT_KERNEL_RWX",
        "CONFIG_ARM64_UAO",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_UNMAP_KERNEL_AT_EL0",
    ],
    "kernel-4.14": [
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_STRICT_KERNEL_RWX",
        "CONFIG_ARM64_UAO",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_UNMAP_KERNEL_AT_EL0",
        "CONFIG_CFI_CLANG",
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
    ],
    "kernel-4.19": [
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_STRICT_KERNEL_RWX",
        "CONFIG_ARM64_UAO",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_UNMAP_KERNEL_AT_EL0",
        "CONFIG_CFI_CLANG",
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
    ],
    "kernel-5.4": [
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_STRICT_KERNEL_RWX",
        "CONFIG_ARM64_UAO",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_UNMAP_KERNEL_AT_EL0",
        "CONFIG_CFI_CLANG",
        "CONFIG_SLAB_FREELIST_HARDENED",  
        "KSMA-protection",
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
    ],
    "kernel-5.10": [
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_STRICT_KERNEL_RWX",
        "CONFIG_ARM64_UAO",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_UNMAP_KERNEL_AT_EL0",
        "CONFIG_CFI_CLANG",
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
        "KSMA-protection",
    ],
    "kernel-5.15": [
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_STRICT_KERNEL_RWX",
        "CONFIG_ARM64_UAO",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_UNMAP_KERNEL_AT_EL0",
        "CONFIG_CFI_CLANG",
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
        "KSMA-protection",
        "kmalloc-cg",
    ],
    "kernel-6.1": [
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_STRICT_KERNEL_RWX",
        "CONFIG_ARM64_UAO",
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_UNMAP_KERNEL_AT_EL0",
        "CONFIG_CFI_CLANG",
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
        "KSMA-protection",
        "kmalloc-cg",
    ],
}

CONFIG_PROTECTIONS = [
    # "CONFIG_ARM64_VA_BITS_39",
    # "CONFIG_ARM64_VA_BITS_48",

    "CONFIG_DEBUG_LIST",
    "CONFIG_LIST_HARDENED",
    "CONFIG_BUG_ON_DATA_CORRUPTION",
    
    "CONFIG_BPF_JIT_ALWAYS_ON",
    
    "CONFIG_CFI_CLANG",

    "kmalloc-cg",

    "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
    # "CONFIG_INIT_ON_FREE_DEFAULT_ON",
    
    "CONFIG_ARM64_UAO",

    "CONFIG_SLAB_FREELIST_HARDENED",

    "KSMA-protection", # CONFIG_PG_DIR_RO -> Vivo, all kind of RKPs -> Samsung
    
    "CONFIG_RANDOMIZE_BASE",
    "CONFIG_RELOCATABLE",
    
    "CONFIG_STRICT_KERNEL_RWX",
    "CONFIG_DEBUG_RODATA",

    "CONFIG_ARM64_PAN",

    # "CONFIG_ARM64_SW_TTBR0_PAN",

    "CONFIG_SLAB_FREELIST_RANDOM",

    "CONFIG_UNMAP_KERNEL_AT_EL0",

    # "CONFIG_SHUFFLE_PAGE_ALLOCATOR",

    # "CONFIG_HARDENED_USERCOPY",

    # "CONFIG_STACKPROTECTOR_STRONG",

    # "CONFIG_INIT_STACK_ALL_ZERO",
]

CONFIG_SAMSUNG_PROTECTIONS = [
    "CONFIG_UH_RKP",
    "CONFIG_FASTUH_RKP",
    "CONFIG_TIMA_RKP",
    "CONFIG_RKP",
    "CONFIG_KDP",
    "CONFIG_FASTUH_KDP",
    "CONFIG_RKP_KDP",
    "CONFIG_RKP_CFP_JOPP",
    "CONFIG_RKP_CFP_ROPP",
    "Samsung-Dirty-PageTable-protection",
    "Samsung-KSMA-protection",
    "Samsung RKP",
]

CONFIG_HUAWEI_PROTECTIONS = [
    "CONFIG_HHEE",
]

KERNELS = [
    "kernel-3.18",
    "kernel-4.4",
    "kernel-4.9",
    "kernel-4.14",
    "kernel-4.19",
    "kernel-5.4",
    "kernel-5.10",
    "kernel-5.15",
    "kernel-6.1"
]
class Stat:
    def __init__(self, kernel_version: str, is_samsung: bool, is_huawei: bool) -> None:
        self.kernel_version = kernel_version
        self.__prot_results = {}
        self.__count = 0
        if is_samsung:
            prots = CONFIG_PROTECTIONS + CONFIG_SAMSUNG_PROTECTIONS
        elif is_huawei:
            prots = CONFIG_PROTECTIONS + CONFIG_HUAWEI_PROTECTIONS
        else:
            prots = CONFIG_PROTECTIONS
        for prot in prots:
            self.__prot_results[prot] = 0
    def inc(self) -> None:
        self.__count += 1
    def cnt(self) -> int:
        return self.__count
    def mitigate(self, prot: str) -> None:
        self.__prot_results[prot] += 1
    def get_prot(self, prot: str) -> int:
        return self.__prot_results[prot]
    def get_norm_prot(self, prot: str) -> int:
        if self.__count == 0:
            return 0
        return self.__prot_results[prot]/self.__count

ONE_DAYS_MITIGATED = {
    "CVE-2019-2215": [
        "CONFIG_DEBUG_LIST", # unlink primitive
        "CONFIG_ARM64_UAO", # addr_limit overwrite -> not effective
        "CONFIG_HHEE"
    ],
    "CVE-2019-2025": [
        "CONFIG_DEBUG_LIST" # unlink primitive
    ],
    "CVE-2020-0030": [
        "CONFIG_DEBUG_LIST", # unlink primitive
        "CONFIG_ARM64_UAO", # addr_limit overwrite -> not effective
        "CONFIG_HHEE"
    ],
    "CVE-2021-1968, CVE-2021-1969, CVE-2021-1940": [
        "CONFIG_CFI_CLANG", # call ret2bpf
        "CONFIG_BPF_JIT_ALWAYS_ON", # ret2bpf
    ],
    "CVE-2021-0920": [
        "CONFIG_DEBUG_LIST", # unlink primitive
        "kmalloc-cg", # pipe_buffer WP
    ],
    "CVE-2021-1905": [
        "CONFIG_CFI_CLANG", # call ret2bpf
        "CONFIG_BPF_JIT_ALWAYS_ON", # ret2bpf
    ],
    "CVE-2022-22265": [
        "kmalloc-cg", # stability for pipe_buffer WP
    ],
    "CVE-2021-25369, CVE-2021-25370": [
        "kmalloc-cg", # file reclaim
        "CONFIG_ARM64_UAO", # addr_limit overwrite -> not effective
        "CONFIG_HHEE"
    ],
    "CVE-2016-3809, CVE-2021-0399": [
        "CONFIG_CFI_CLANG", # call ret2bpf
        "kmalloc-cg", # seq_file overwrite
        "CONFIG_BPF_JIT_ALWAYS_ON", # ret2bpf
    ],
    "CVE-2022-20409": [
        "kmalloc-cg", # pipe_buffer WP
    ],
    "CVE-2023-21400": [
        "kmalloc-cg", # seq_file spray
        "Samsung-Dirty-PageTable-protection",
        "CONFIG_UH_RKP",
        "CONFIG_RKP"
    ],
    "CVE-2022-28350": [
        "Samsung-Dirty-PageTable-protection",
        "CONFIG_UH_RKP",
        "CONFIG_RKP"
    ],
    "CVE-2020-29661": [
        "Samsung-Dirty-PageTable-protection",
        "CONFIG_UH_RKP",
        "CONFIG_RKP"
    ],
    "CVE-2021-22600": [
        "kmalloc-cg", # pipe_buffer WP
    ],
    "CVE-2020-0423": [
        "CONFIG_DEBUG_LIST", # unlink primitive
        "CONFIG_UH_RKP",
        "CONFIG_RKP",
        "Samsung-KSMA-protection",
        "KSMA-protection", # not effective
        "CONFIG_HHEE"
    ],
    "CVE-2022-22057": [
        "CONFIG_SLAB_FREELIST_HARDENED", # unlink primitive
        "CONFIG_UH_RKP",
        "CONFIG_RKP",
        "Samsung-KSMA-protection",
        "KSMA-protection", # not effective
        "CONFIG_HHEE"
    ],
    "CVE-2023-26083, CVE-2023-0266": [
    ],
    "CVE-2020-0041": [
        "CONFIG_DEBUG_LIST", # unlink primitive
    ],
    "CVE-2019-2205": [
        "CONFIG_DEBUG_LIST" # unlink primitive
    ],
    "CVE-2019-2025-1": [
        "CONFIG_DEBUG_LIST", # unlink primitive
        "CONFIG_UH_RKP",
        "CONFIG_RKP",
        "Samsung-KSMA-protection",
        "KSMA-protection", # not effective
        "CONFIG_HHEE"
    ],
    "CVE-2020-3680": [
        "CONFIG_DEBUG_LIST", # unlink primitive,
        "CONFIG_UH_RKP",
        "CONFIG_RKP",
        "Samsung-KSMA-protection",
        "KSMA-protection", # not effective
        "CONFIG_HHEE"
    ],
    "CVE-2022-20421": [
        "kmalloc-cg", # pipe_buffer WP
    ],
    "CVE-2022-0847": [
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON" # uninit variable
    ],
    "CVE-2021-4154": [
    ],
    "CVE-2021-38001": [
        "CONFIG_CFI_CLANG", # call ret2bpf
        "CONFIG_BPF_JIT_ALWAYS_ON" # ret2bpf
    ],
    "NO_NUMBER": [
        "CONFIG_SLAB_FREELIST_HARDENED",
        "kmalloc-cg", # pipe_buffer WP
    ]
}
class StatOneDays:
    def __init__(self, kernel_version: str) -> None:
        self.kernel_version = kernel_version
        self.one_days = {}
        for one_day in ONE_DAYS_MITIGATED.keys():
            self.one_days[one_day] = 1 # does work
    def mitigate(self, prot: str) -> None:
        for _od,_p in ONE_DAYS_MITIGATED.items():
            # print("    prot {}".format(prot))
            # print("    _p   {}".format(_p))
            if prot in _p:
                # print("set {} to 0".format(_od))
                self.one_days[_od] = 0
    def working_one_days_count(self) -> int:
        count = 0
        for _p in self.one_days.values():
            count += _p
        return count
    def working_one_days(self) -> list:
        one_days = [_od for _od,_p in self.one_days.items() if _p == 1]
        return one_days

CONFIG_PROTECTIONS_KERNEL_ELF = {
    "CONFIG_SLAB_FREELIST_HARDENED": [
        {"parent": "__kmem_cache_create", "call": "get_random_u64"}, # calls get_random_long in kernel.elf
        {"parent": "kmem_cache_open", "call": "get_random_u64"} # calls get_random_long in kernel.elf
    ]
}
CONFIG_PROTECTIONS_KSMA = {
    "kallsyms": "swapper_pgdir_lock",
    "ros": ["swapper_pg_dir", "tramp_pg_dir"],
}
CONFIG_PROTECTIONS_SW_PAN = "emulated: Privileged Access Never (PAN) using TTBR0_EL1 switching"
CONFIG_PROTECTIONS_KALLSYMS = {
    "CONFIG_DEBUG_LIST": ["__list_add_valid", "__list_del_entry_valid", "__list_add", "__list_del_entry"],
    "CONFIG_STRICT_KERNEL_RWX": ["set_debug_rodata", "mark_rodata_ro"],
    "CONFIG_BPF_JIT_ALWAYS_ON": ["___bpf_prog_run", "__bpf_prog_run"], # not
    "CONFIG_CFI_CLANG": ["cfi_module_add", "cfi_module_remove"],
    "CONFIG_INIT_ON_ALLOC_DEFAULT_ON": ["init_on_alloc"],
    "CONFIG_ARM64_UAO": ["uao_thread_switch", "cpu_enable_uao"],
    "CONFIG_RANDOMIZE_BASE": ["kaslr_init", "kaslr_early_init", "get_kaslr_seed"],
    "CONFIG_UNMAP_KERNEL_AT_EL0": ["tramp_pg_dir"],
    # "CONFIG_SHUFFLE_PAGE_ALLOCATOR" : ["__shuffle_free_memory"],
    "CONFIG_SLAB_FREELIST_RANDOM": ["cache_random_seq_create", "cache_random_seq_destroy"],
    "CONFIG_ARM64_PAN": ["cpu_enable_pan", "reserved_ttbr0"], # reserved_ttbr0 von CONFIG_ARM64_SW_TTBR0_PAN
    # "CONFIG_HARDENED_USERCOPY": ["usercopy_abort"],
    "CONFIG_HHEE": ["hkip_addr_limit_bits"],
}

###########################################################################
def find_protection_firmware(f_dir: str, stats: dict, do_print: bool = True):
    p = "{}/out/kallsyms".format(f_dir)
    if os.path.exists(p) == False:
        print("[!] {} does not exist".format(p))
        return
    # print("[*] {}".format(f_dir))
    kallsyms = open(p, "r").read()
    version = re.findall(r"Version string: Linux version [3,4,5,6]\.[0-9]*\.[0-9]*", kallsyms)[0][30:]
    kernel_version = "kernel-"+re.findall(r"Version string: Linux version [3,4,5,6]\.[0-9]*", kallsyms)[0][30:]
    if kernel_version not in stats:
        return

    def no_print(_: str):
        pass
    if do_print == True:
        print_fn = print
    else:
        print_fn = no_print
    print_fn("[*] {} with {}".format(f_dir, version))
    prots = get_firmware_protections(f_dir, kallsyms, kernel_version)
    for prot,c in prots.items():
        if c == True:
            print_fn("  [+] prot {} ENABLED".format(prot))
            if (prot == "CONFIG_ARM64_UAO" or prot == "KSMA-protection"):# and \
                # not ("huawei" in f_dir and prot == "KSMA-protection"):
                continue
            stats[kernel_version].mitigate(prot)
        else:
            print_fn("  [!] prot {} DISABLED".format(prot))
    stats[kernel_version].inc()
    print_fn("")

NOT_PRINTED = [
    "CONFIG_LIST_HARDENED",
    "CONFIG_BUG_ON_DATA_CORRUPTION",
    "CONFIG_DEBUG_RODATA",
    "CONFIG_RELOCATABLE",
    "CONFIG_UH_RKP",
    "CONFIG_FASTUH_RKP",
    "CONFIG_TIMA_RKP",
    "CONFIG_RKP",
    "CONFIG_KDP",
    "CONFIG_FASTUH_KDP",
    "CONFIG_RKP_KDP",
    "CONFIG_RKP_CFP_JOPP",
    "CONFIG_RKP_CFP_ROPP",
    "Samsung-Dirty-PageTable-protection",
    "Samsung-KSMA-protection",
    "CONFIG_SHUFFLE_PAGE_ALLOCATOR",
]
###########################################################################
def print_results(stats: dict, is_samsung: bool = False, is_huawei: bool = False):
    print("\nresults:")
    prot_results = {}
    count = 0
    if is_samsung:
        prots = CONFIG_PROTECTIONS + CONFIG_SAMSUNG_PROTECTIONS
    if is_huawei:
        prots = CONFIG_PROTECTIONS + CONFIG_HUAWEI_PROTECTIONS
    else:
        prots = CONFIG_PROTECTIONS
    for prot in prots:
        prot_results[prot] = 0
    for kernel_version in KERNELS:
        count += stats[kernel_version].cnt()
    for kernel_version in KERNELS:
        if kernel_version not in stats:
            continue
        if stats[kernel_version].cnt() == 0:
            continue
        print("  {} with {:0.2f} % cnt {}".format(kernel_version, stats[kernel_version].cnt()/count*100, stats[kernel_version].cnt()))
        for prot in prots:
            prot_results[prot] += stats[kernel_version].get_prot(prot)
            if prot in NOT_PRINTED:
                continue
            print("    prot {:0.2f} % {}".format(stats[kernel_version].get_norm_prot(prot)*100, prot))
    print("  total cnt {}".format(count))
    if count == 0:
        return
    for prot in prots:
        if prot in NOT_PRINTED:
            continue
        print("    prot {:0.2f} % {}".format(prot_results[prot]*100/count, prot))
    return prot_results,count,prots

###########################################################################
def get_firmware_protections(f_dir: str, kallsyms: str, kernel_version: str):
    prots = {}
    # kallsyms generic
    for prot,symbs in CONFIG_PROTECTIONS_KALLSYMS.items():
        count = 0
        for symb in symbs:
            count += "{}\n".format(symb) in kallsyms
        if prot == "CONFIG_BPF_JIT_ALWAYS_ON":
            count = not count
        if count == 0:
            # print("[!]   PROT {} disabled".format(prot))
            prots[prot] = False
        elif count != len(symbs):
            # print("[?]   PROT {} maybe enabled".format(prot))
            # print("[+]   PROT {} enabled".format(prot))
            prots[prot] = True
        else:
            # print("[+]   PROT {} enabled".format(prot))
            prots[prot] = True
    
    # aarch64-linux-gnu-objdump -D kernel.elf
    for prot,entries in CONFIG_PROTECTIONS_KERNEL_ELF.items():
        kallsyms_lines = kallsyms.split("\n")
        found = False
        for entry in entries:
            call = entry["call"]
            parent = entry["parent"]
            parent_addr = 0
            for kallsyms_line in kallsyms_lines:
                if parent in kallsyms_line:
                    parent_addr = int(re.findall(r"[0-9a-f]* ", kallsyms_line)[0][:-1], 16)
            
            # print("[*]   read addr {} of {}".format(parent_addr, "{}/out/kernel.elf".format(f_dir)))
            result = subprocess.run(["aarch64-linux-gnu-objdump", "-D", "{}/out/kernel.elf".format(f_dir), "--start-address={}".format(parent_addr), "--stop-address={}".format(parent_addr+0x1000)], stdout=subprocess.PIPE)
            kernel_elf = result.stdout.decode("utf-8").split("\n")
            for line in kernel_elf:
                if call in line:
                    found = True
                    break
        prots[prot] = found
        # if found == True:
        #     print("[+]   PROT {} ".format(prot))
        # else:
        #     print("[!]   PROT {} disabled".format(prot))

    # CONFIG_ARM64_SW_TTBR0_PAN protection
    if prots["CONFIG_ARM64_PAN"] == False:
        result = subprocess.run(["strings", "{}/out/kernel.elf".format(f_dir)], stdout=subprocess.PIPE)
        kernel_strings = result.stdout.decode("utf-8")
        prots["CONFIG_ARM64_PAN"] = CONFIG_PROTECTIONS_SW_PAN in kernel_strings

    # KSMA protection
    if CONFIG_PROTECTIONS_KSMA["kallsyms"] in kallsyms:
        kallsyms_lines = kallsyms.split("\n")
        __start_rodata = 0
        __init_begin = 0
        for kallsyms_line in kallsyms_lines:
            if "__start_rodata" in kallsyms_line:
                __start_rodata = int(kallsyms_line[:16], 16)
            if "__init_begin" in kallsyms_line:
                __init_begin = int(kallsyms_line[:16], 16)
        enabled = True
        for ro in CONFIG_PROTECTIONS_KSMA["ros"]:
            ro_data = 0
            for kallsyms_line in kallsyms_lines:
                if ro in kallsyms_line:
                    ro_data = int(kallsyms_line[:16], 16)
            if ro_data != 0 and (__start_rodata == 0 or __init_begin == 0):
                enabled = False
                print("[?]   {} KSMA looks strange".format(f_dir))
            elif __start_rodata < ro_data and ro_data < __init_begin:
                pass # enabled
            else:
                enabled = False
        prots["KSMA-protection"] = enabled
        # if enabled == True:
        #     print("[+]   PROT KSMA-protection enabled")
        # else:
        #     print("[!]   PROT KSMA-protection disabled")
    else:
        prots["KSMA-protection"] = False
        # print("[!]   PROT KSMA-protection disabled")

    if "samsung" in f_dir:
        config_rkp = "rkp_init\n" in kallsyms
        dirty_pagetable_protection = config_rkp
        ksma_protection = config_rkp
        with open("{}/../../dirty-pagetable.json".format(f_dir), "r") as f:
            models = json.loads(f.read())
            for model in models:
                if model.lower() in f_dir.lower():
                    dirty_pagetable_protection = False
        prots["Samsung-Dirty-PageTable-protection"] = dirty_pagetable_protection
        prots["Samsung-KSMA-protection"] = ksma_protection
        prots["Samsung RKP"] = config_rkp

    prots["kmalloc-cg"] = kernel_version == "kernel-5.15" or kernel_version == "kernel-6.1"
    prots["CONFIG_ARM64_UAO"] |= kernel_version == "kernel-5.15" or kernel_version == "kernel-6.1"
    return prots

###########################################################################
def print_one_days(stats: dict):
    cves = [cve for cve in ONE_DAYS_MITIGATED.keys()]
    print("\ncves:")
    for cve in cves:
        count = 0
        for stat_od in stats.values():
            ods = stat_od.working_one_days()
            if cve in ods:
                count += 1
        # if count == 0:
        #     continue
        print("  {:45s}: {:6d}/{}\t{:.1f} %".format(cve, count, len(stats.values()), 100*count/len(stats.values())))

###########################################################################
def score_of_one_days(stats: dict):
    diff = {}
    cves = [cve for cve in ONE_DAYS_MITIGATED.keys()]
    for cve in cves:
        count = 0
        for stat_od in stats.values():
            ods = stat_od.working_one_days()
            if cve in ods:
                count += 1
        if count in diff:
            diff[count] += 1
        else:
            diff[count] = 1
    od_counts = np.zeros(len(stats)+1)
    # devs = np.linspace(0, 100, len(stats)+1)
    devs = np.linspace(0, len(stats), len(stats)+1)
    accom = 0
    od = len(cves)
    for i in range(len(stats)):
        if i in diff:
            od -= diff[i]
        accom += od
        od_counts[i+1] = od
    od_counts[0] = od_counts[1]
    return {"devs": devs, "od_counts": od_counts, "accom": accom, "cves": cves}

###########################################################################
def one_day_analysis_firmware(f_dir: str, stats: dict):
    p = "{}/out/kallsyms".format(f_dir)
    if os.path.exists(p) == False:
        print("[!] {} does not exist".format(p))
        return
    kallsyms = open(p, "r").read()
    # print("[*] {}".format(f_dir))
    version = re.findall(r"Version string: Linux version [3,4,5,6]\.[0-9]*\.[0-9]*", kallsyms)[0][30:]
    kernel_version = "kernel-"+re.findall(r"Version string: Linux version [3,4,5,6]\.[0-9]*", kallsyms)[0][30:]
    stats[f_dir] = StatOneDays(kernel_version)

    print("[*] {} with {}".format(f_dir, version))
    configs = get_firmware_protections(f_dir, kallsyms, kernel_version)
    for prot,c in configs.items():
        if c == True:
            print("  [+] prot {} ENABLED".format(prot))
            if (prot == "CONFIG_ARM64_UAO" or prot == "KSMA-protection"):
                continue
            stats[f_dir].mitigate(prot)
        else:
            print("  [!] prot {} DISABLED".format(prot))
    print("[*] score {}".format(sum(stats[f_dir].one_days.values())))
    print("")

###########################################################################
def do_one_day_analysis_firmware():
    dir = config["dir"]
    f_dirs = ["{}/firmwares/{}".format(dir, f_dir) for f_dir in os.listdir("{}/firmwares".format(dir))]
    stats = {}
    for f_dir in f_dirs:
        one_day_analysis_firmware(f_dir, stats)
    print_one_days(stats)
    score = score_of_one_days(stats)
    name = "output/{}_one_day_analysis.csv".format(dir)
    with open(name, "w") as f:
        spamwriter = csv.writer(f, delimiter=';')
        spamwriter.writerow(["#devices", "#one-day-exploitation-flow"])
        spamwriter.writerows([[d,od] for od,d in zip(score["od_counts"],score["devs"])])
    score = 100*score["accom"]/len(score["cves"])/len(stats)
    print("\nscore {:.1f}".format(100-score))

###########################################################################
def do_one_day_analysis_all():
    one_days = config["one-days"]
    stats = {}
    for one_day in one_days:
        dir = one_day["dir"]
        print("dir {}".format(dir))
        f_dirs = ["{}/firmwares/{}".format(dir, f_dir) for f_dir in os.listdir("{}/firmwares".format(dir))]
        for f_dir in f_dirs:
            one_day_analysis_firmware(f_dir, stats)
    print_one_days(stats)
    score = score_of_one_days(stats)
    name = "output/one_day_analysis_all.csv"
    with open(name, "w") as f:
        spamwriter = csv.writer(f, delimiter=';')
        spamwriter.writerow(["#devices", "#one-day-exploitation-flow"])
        spamwriter.writerows([[d,od] for od,d in zip(score["od_counts"],score["devs"])])
    score = 100*score["accom"]/len(score["cves"])/len(stats)
    print("\nscore {:.1f}".format(100-score))

###########################################################################
def do_find_all_protection():
    find_prots = config["all"]
    stats = {}
    for kernel_version in KERNELS:
        stats[kernel_version] = Stat(kernel_version, True, True)
    for find_prot in find_prots:
        dir = find_prot["dir"]
        print("dir {}".format(dir))
        # find protection firmware
        f_dirs = ["{}/firmwares/{}".format(dir, f_dir) for f_dir in os.listdir("{}/firmwares".format(dir))]
        for f_dir in f_dirs:
            find_protection_firmware(f_dir, stats)
    print_results(stats)

###########################################################################
def do_find_protection_firmware():
    dir = config["dir"]
    f_dirs = ["{}/firmwares/{}".format(dir, f_dir) for f_dir in os.listdir("{}/firmwares".format(dir))]
    stats = {}
    for kernel_version in KERNELS:
        stats[kernel_version] = Stat(kernel_version, "samsung" in dir, "huawei" in dir)
    for f_dir in f_dirs:
        find_protection_firmware(f_dir, stats)
    prot_results,count,prots = print_results(stats, "samsung" in dir, "huawei" in dir)
    name = "output/{}_find_protection.csv".format(dir)
    with open(name.format(dir), "w") as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(["#defense", "#percent"])
        writer.writerows([[prot, prot_results[prot]*100/count] for prot in prots if prot not in NOT_PRINTED])

###########################################################################
def do_one_day_analysis_per_kernel_version_ideal():
    print("[*] start ideal one day per kernel version")
    results = []
    for kv,ms in VERSION_TO_MITIGATIONS.items():
        count = 0
        # print("  [*] {}: {}".format(kv, ms))
        for od in ONE_DAYS_MITIGATED.values():
            for m in ms:
                if m in od:
                    count += 1
                    break
        results.append([kv,len(ONE_DAYS_MITIGATED)-count])
    with open("output/ground_truth_one_day_analysis_per_kernel_version.csv", "w") as f:
        spamwriter = csv.writer(f, delimiter=';')
        spamwriter.writerow(["kernel-version", "count", "one-day-mean", "one-day-std"])
        for result in results:
            spamwriter.writerow([result[0].replace("kernel-", "v"), 1, result[1], 0])
            print("[*] {:15s} {:4d} {:.1f} {:.1f}".format(result[0], 1, result[1], 0))

###########################################################################
def one_day_analysis_per_kernel_version(f_dir: str, stats: dict):
    p = "{}/out/kallsyms".format(f_dir)
    if os.path.exists(p) == False:
        print("[!] {} does not exist".format(p))
        return
    kallsyms = open(p, "r").read()
    # print("[*] {}".format(f_dir))
    version = re.findall(r"Version string: Linux version [3,4,5,6]\.[0-9]*\.[0-9]*", kallsyms)[0][30:]
    kernel_version = "kernel-"+re.findall(r"Version string: Linux version [3,4,5,6]\.[0-9]*", kallsyms)[0][30:]
    stat = StatOneDays(kernel_version)

    print("[*] {} with {}".format(f_dir, version))
    configs = get_firmware_protections(f_dir, kallsyms, kernel_version)
    for prot,c in configs.items():
        if c == True:
            print("  [+] prot {} ENABLED".format(prot))
            if (prot == "CONFIG_ARM64_UAO" or prot == "KSMA-protection"):
                continue
            stat.mitigate(prot)
        else:
            print("  [!] prot {} DISABLED".format(prot))
    if kernel_version in stats:
        stats[kernel_version].append(stat)
    else:
        stats[kernel_version] = [stat]
    print("")

###########################################################################
def do_one_day_analysis_per_kernel_version():
    dir = config["dir"]
    f_dirs = ["{}/firmwares/{}".format(dir, f_dir) for f_dir in os.listdir("{}/firmwares".format(dir))]
    stats = {}
    for f_dir in f_dirs:
        one_day_analysis_per_kernel_version(f_dir, stats)
    results = {}
    total = 0
    cves = [cve for cve in ONE_DAYS_MITIGATED.keys()]
    for kernel_version,_stats in stats.items():
        results[kernel_version] = []
        total += len(_stats)
        for stat in _stats:
            count = 0
            for cve in cves:
                ods = stat.working_one_days()
                if cve in ods:
                    count += 1
            results[kernel_version].append(count)
    with open("output/{}_one_day_analysis_per_kernel_version.csv".format(dir), "w") as f:
        spamwriter = csv.writer(f, delimiter=';')
        spamwriter.writerow(["kernel-version", "count", "countp", "one-day-mean", "one-day-std"])
        for kernel_version,result in results.items():
            result_mean = np.mean(result)
            result_std = np.std(result)
            std = result_std/result_mean*100
            spamwriter.writerow([kernel_version.replace("kernel-", "v"), len(result), len(result)/total, result_mean, result_std])
            print("[*] {:15s} {:4d} {:.1f} {:.1f}".format(kernel_version, len(result), result_mean, std))

###########################################################################
if config["type"] == "one-day-analysis-firmware":
    do_one_day_analysis_firmware()
elif config["type"] == "find-protection-firmware":
    do_find_protection_firmware()
elif config["type"] == "find-protection-all":
    do_find_all_protection()
elif config["type"] == "one-day-analysis-all":
    do_one_day_analysis_all()
elif config["type"] == "one-day-analysis-per-kernel-version-ideal":
    do_one_day_analysis_per_kernel_version_ideal()
elif config["type"] == "one-day-analysis-per-kernel-version":
    do_one_day_analysis_per_kernel_version()
else:
    print("no valid type")
    exit(-1)
