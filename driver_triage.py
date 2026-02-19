# driver_triage.py - Ghidra Headless Script for Cthaeh Driver Triage
# Run via: analyzeHeadless.bat <proj> <name> -import <driver.sys> -postScript driver_triage.py
#
# Scores Windows kernel drivers on vulnerability indicators.
# Output: prints JSON summary to stdout (captured by orchestrator).
#
# "The Cthaeh does not lie. The Cthaeh sees the true shape of the world."
#
# @category Security
# @author Jeff Barron

import json
import re
import os

# Ghidra imports (available in Ghidra scripting environment)
from ghidra.program.model.symbol import SourceType
from ghidra.program.util import DefinedDataIterator


# --- Scoring Weights Configuration ---
# All point values in one place for easy tuning.
# Positive = increases risk score. Negative = reduces risk score.
WEIGHTS = {
    # Device creation & IOCTL handling
    "insecure_device_creation": 15,
    "has_ioctl_handler": 10,
    "method_neither_heavy": 10,
    "file_any_access_heavy": 10,
    "no_probe_functions": 10,

    # Pool & memory operations
    "deprecated_pool_alloc": 10,
    "maps_physical_memory": 15,
    "maps_memory_section": 10,
    "maps_locked_pages": 10,
    "maps_locked_pages_cache": 10,
    "object_reference": 10,
    "file_operations": 5,
    "file_write": 5,
    "file_read": 5,
    "memcpy_present": 5,
    "memmove_present": 3,

    # BYOVD
    "byovd_process_killer": 20,

    # Physical memory
    "physical_memory_rw": 15,

    # MSR / CR access
    "msr_write": 25,
    "msr_read": 15,
    "control_register_access": 20,

    # Token stealing
    "token_steal_primitives": 15,
    "process_lookup": 5,

    # Known-bad codebases
    "winio_codebase": 25,
    "dse_bypass_indicator": 20,

    # Firmware / disk / registry
    "firmware_bus_access": 15,
    "raw_disk_access": 15,
    "kernel_registry_write": 10,

    # Driver structure
    "thin_driver_critical": 15,
    "thin_driver": 8,
    "unchecked_copy": 20,
    "weak_copy_validation": 10,

    # Internal validation (negative = FP reducer)
    "has_internal_validation": -10,

    # Vendor context
    "vendor_cna_bounty": 20,
    "vendor_cna": 10,

    # Driver class
    "wifi_driver": 15,
    "audio_class_driver": -15,
    "windows_inbox_driver": -15,  # Raised from -10

    # IOCTL surface
    "massive_ioctl_surface": 15,
    "large_ioctl_surface": 10,
    "moderate_ioctl_surface": 5,

    # Device interface
    "named_device": 15,
    "device_interface_guid": 5,

    # LOLDrivers
    "loldrivers_known": -30,  # Raised from -20 (stronger deprioritization)

    # v4.1 research-driven checks
    "symlink_no_acl": 20,
    "has_auth_checks": 5,
    "no_auth_imports": 10,
    "usb_request_forwarding": 10,
    "bt_driver_crypto": 15,
    "bt_driver": 5,
    "efuse_access": 20,
    "wmi_method_execution": 15,
    "physical_memory_section": 25,
    "port_io_rw": 20,
    "port_io_read": 10,

    # Compound primitives
    "compound_god_mode": 15,
    "compound_easy_target": 10,
    "compound_wide_open": 10,

    # v4.2: vuln pattern composite (from real findings)
    "vuln_pattern_composite": 25,

    # v5: driver class ranking
    "dangerous_driver_class": 10,

    # HVCI
    "likely_hvci_incompatible": 5,

    # Communication capability (user-mode bridge)
    "comms_capability": 10,

    # PPL killer potential
    "ppl_killer_potential": 25,

    # WHQL-signed / inbox penalty (stronger negative scoring)
    "whql_signed_inbox": -20,

    # v5: CVE history
    "has_prior_cves": 15,
    "has_recent_cves_2yr": 10,

    # v4.3: research-driven additions
    "wdf_device_interface": -15,   # WDF + device interface = SDDL-protected (nvpcf FP lesson)
    "wdm_direct_device": 10,       # WDM + IoCreateDevice = weaker security model
    "uefi_variable_access": 15,    # ExGetFirmwareEnvironmentVariable = UEFI manipulation
    "hardcoded_crypto_key": 10,    # Hardcoded keys/seeds for firmware decryption
    "hci_command_passthrough": 20, # Raw HCI command passthrough to BT hardware
    "urb_from_user_input": 20,     # USB Request Block built from user-controlled data
    "no_inputbuffer_length_check": 15,  # Missing InputBufferLength validation before parsing
    "previousmode_relevant": 0,    # Informational: PreviousMode attack surface (new mitigation in 24H2)

    # v7: AwesomeMalDevLinks-inspired checks (#7-#12)
    # Memory corruption patterns (#7)
    "uaf_indicator": 20,           # Free-then-use pattern in IOCTL path
    "double_free_indicator": 20,   # Multiple frees of same allocation
    "free_without_null": 10,       # ExFreePool without zeroing pointer
    "ob_deref_heavy": 10,          # Heavy ObDereferenceObject usage (ref count bugs)

    # Expanded BYOVD primitives (#9)
    "byovd_arb_read": 25,         # MmMapIoSpace in IOCTL path (arbitrary kernel read)
    "byovd_arb_write": 30,        # MmMapIoSpace + write in IOCTL path
    "byovd_kernel_execute": 30,   # KeInsertQueueApc/ExQueueWorkItem from user data
    "byovd_pid_terminate": 20,    # ZwOpenProcess + ZwTerminateProcess combo

    # IORING surface (#10)
    "ioring_surface": 15,         # IORING-related APIs or shared memory patterns

    # Killer driver patterns (#11)
    "killer_enum_terminate": 20,   # Process enumeration + termination combo
    "killer_service_control": 15,  # SCM API usage from kernel (unusual)
    "killer_callback_removal": 25, # PsSetCreateProcessNotifyRoutine remove / ObUnRegisterCallbacks
    "killer_minifilter_unload": 20,# FltUnregisterFilter from non-filter driver
    "killer_edr_strings": 15,     # EDR/AV product name strings in driver

    # Bloatware/OEM prioritization (#12)
    "oem_bloatware_vendor": 10,    # Known bloatware-heavy OEM vendor
    "utility_driver_strings": 10,  # RGB/overclock/fan/LED utility patterns
    "driver_age_5plus": 10,        # PE timestamp > 5 years old

    # Kernel Rhabdomancer - candidate point analysis
    "candidate_tier0_ioctl": 25,   # Critical API in IOCTL dispatch path
    "candidate_tier0_other": 10,   # Critical API outside IOCTL path
    "candidate_tier1_ioctl": 8,    # Interesting APIs in IOCTL path (3+)
    "candidate_no_validation": 15, # Dangerous API in IOCTL path without ProbeForRead/Write
}

# Scoring thresholds
THRESHOLDS = {
    "CRITICAL": 250,  # ~1.2% of drivers. Drop everything and analyze.
    "HIGH": 150,      # ~15%. Strong candidates, investigate soon.
    "MEDIUM": 75,     # Worth a look.
    "LOW": 30,        # Probably boring.
}


def get_weight(check_id):
    """Get the weight for a check, defaulting to 0 if not in config."""
    return WEIGHTS.get(check_id, 0)


# --- Known FP / Skip List ---
def load_investigated():
    """Load known false positives / already-investigated drivers."""
    candidates = []
    
    # 1. Ghidra's sourceFile (Jython scripting env)
    try:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(sourceFile.getAbsolutePath())), "investigated.json"))
    except:
        pass
    
    # 2. Python __file__ (CPython / direct invocation)
    try:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "investigated.json"))
    except:
        pass
    
    # 3. Ghidra script directories (getScriptDirectories if available)
    try:
        from ghidra.app.script import GhidraScriptUtil
        for d in GhidraScriptUtil.getScriptDirectories():
            candidates.append(os.path.join(d.getAbsolutePath(), "investigated.json"))
    except:
        pass
    
    # 4. Current working directory
    candidates.append(os.path.join(os.getcwd(), "investigated.json"))
    
    # 5. Environment variable override
    env_path = os.environ.get("CTHAEH_FP_PATH")
    if env_path:
        candidates.insert(0, env_path)
    
    for fp_path in candidates:
        try:
            with open(fp_path, "r") as f:
                data = json.load(f)
                result = data.get("investigated", data.get("skip_drivers", {}))
                if result:
                    print("investigated.json loaded from: %s (%d entries)" % (fp_path, len(result)))
                    return result
        except:
            continue
    
    print("WARNING: investigated.json not found in any search path")
    return {}


INVESTIGATED = load_investigated()


def load_driver_cves():
    """Load known CVE history for driver families from driver_cves.json."""
    candidates = []

    # 1. Ghidra's sourceFile
    try:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(sourceFile.getAbsolutePath())), "driver_cves.json"))
    except:
        pass

    # 2. Python __file__
    try:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "driver_cves.json"))
    except:
        pass

    # 3. Current working directory
    candidates.append(os.path.join(os.getcwd(), "driver_cves.json"))

    # 4. Environment variable override
    env_path = os.environ.get("CTHAEH_CVES_PATH")
    if env_path:
        candidates.insert(0, env_path)

    for cve_path in candidates:
        try:
            with open(cve_path, "r") as f:
                data = json.load(f)
                families = data.get("driver_families", {})
                if families:
                    print("driver_cves.json loaded from: %s (%d families)" % (cve_path, len(families)))
                    return families
        except:
            continue

    print("WARNING: driver_cves.json not found in any search path")
    return {}


DRIVER_CVE_FAMILIES = load_driver_cves()


def get_imports(program):
    """Get all imported function names."""
    imports = set()
    sym_table = program.getSymbolTable()
    for sym in sym_table.getExternalSymbols():
        imports.add(sym.getName().lower())
    return imports


def get_import_dlls(program):
    """Get imported DLL names (lowercase)."""
    dlls = set()
    sym_table = program.getSymbolTable()
    for sym in sym_table.getExternalSymbols():
        parent = sym.getParentNamespace()
        if parent is not None:
            dlls.add(parent.getName().lower())
    return dlls


def get_strings(program):
    """Get all defined strings in the binary."""
    strings = []
    for data in DefinedDataIterator.definedStrings(program):
        val = data.getDefaultValueRepresentation()
        if val:
            strings.append(val.strip('"').strip("'"))
    return strings


def check_device_creation(imports, strings):
    """Check how the driver creates device objects."""
    findings = []
    
    has_create = "iocreatedevice" in imports
    has_create_secure = "iocreatedevicesecure" in imports
    
    if has_create and not has_create_secure:
        findings.append({
            "check": "insecure_device_creation",
            "detail": "Uses IoCreateDevice without IoCreateDeviceSecure",
            "score": get_weight("insecure_device_creation")
        })
    
    return findings


def check_ioctl_handling(imports, program):
    """Check for IOCTL handler patterns."""
    findings = []
    listing = program.getListing()
    func_mgr = program.getFunctionManager()
    
    has_irp_handling = "iofcompleterequest" in imports or "iocompleterequest" in imports
    
    if has_irp_handling:
        findings.append({
            "check": "has_ioctl_handler",
            "detail": "Driver handles IRPs (potential IOCTL attack surface)",
            "score": get_weight("has_ioctl_handler")
        })
    
    return findings


def check_buffer_methods(program):
    """Scan for IOCTL method types in code patterns."""
    findings = []
    listing = program.getListing()
    func_mgr = program.getFunctionManager()
    
    method_neither_count = 0
    method_buffered_count = 0
    file_any_access_count = 0
    
    for func in func_mgr.getFunctions(True):
        body = func.getBody()
        inst_iter = listing.getInstructions(body, True)
        while inst_iter.hasNext():
            inst = inst_iter.next()
            for i in range(inst.getNumOperands()):
                try:
                    scalar = inst.getScalar(i)
                    if scalar is None:
                        continue
                    val = scalar.getUnsignedValue()
                    # IOCTL codes: DeviceType(16) | Access(2) | Function(12) | Method(2)
                    if val > 0x10000 and val < 0xFFFFFFFF:
                        device_type = (val >> 16) & 0xFFFF
                        # Filter: valid device types are <0x100 (MS) or 0x8000+ (vendor)
                        if device_type < 0x100 or device_type >= 0x8000:
                            method = val & 0x3
                            access = (val >> 14) & 0x3
                            if method == 3:
                                method_neither_count += 1
                            elif method == 0:
                                method_buffered_count += 1
                            if access == 0:  # FILE_ANY_ACCESS
                                file_any_access_count += 1
                except:
                    pass
    
    if method_neither_count > 0:
        # Fires on 100% of drivers - only score if unusually high count
        if method_neither_count > 10:
            findings.append({
                "check": "method_neither_heavy",
                "detail": "Found %d potential METHOD_NEITHER IOCTLs (raw user pointers) - unusually high" % method_neither_count,
                "score": get_weight("method_neither_heavy")
            })
        else:
            findings.append({
                "check": "method_neither",
                "detail": "Found %d potential METHOD_NEITHER IOCTLs (raw user pointers)" % method_neither_count,
                "score": 0  # Informational only - fires on everything
            })
    
    if method_buffered_count > 0:
        findings.append({
            "check": "method_buffered",
            "detail": "Found %d potential METHOD_BUFFERED IOCTLs" % method_buffered_count,
            "score": 0  # Informational only - fires on everything
        })
    
    if file_any_access_count > 0:
        # Fires on 100% - only score if unusually high count
        if file_any_access_count > 10:
            findings.append({
                "check": "file_any_access_heavy",
                "detail": "Found %d IOCTLs with FILE_ANY_ACCESS (no privilege check) - unusually high" % file_any_access_count,
                "score": get_weight("file_any_access_heavy")
            })
        else:
            findings.append({
                "check": "file_any_access",
                "detail": "Found %d IOCTLs with FILE_ANY_ACCESS (no privilege check)" % file_any_access_count,
                "score": 0  # Informational only - fires on everything
            })
    
    return findings


def check_validation(imports):
    """Check for presence/absence of buffer validation functions."""
    findings = []
    
    has_probe_read = "probeforread" in imports
    has_probe_write = "probeforwrite" in imports
    has_irp = "iofcompleterequest" in imports or "iocompleterequest" in imports
    
    if has_irp and not has_probe_read and not has_probe_write:
        findings.append({
            "check": "no_probe_functions",
            "detail": "Handles IRPs but never imports ProbeForRead/ProbeForWrite",
            "score": get_weight("no_probe_functions")
        })
    
    return findings


def check_pool_operations(imports):
    """Check for pool allocation patterns."""
    findings = []
    
    pool_funcs = [i for i in imports if "allocatepool" in i or "allocpool" in i]
    
    if pool_funcs:
        if "exallocatepool" in imports:
            findings.append({
                "check": "deprecated_pool_alloc",
                "detail": "Uses deprecated ExAllocatePool (no NX flag)",
                "score": get_weight("deprecated_pool_alloc")
            })
        
        findings.append({
            "check": "has_pool_operations",
            "detail": "Uses pool allocation: %s" % ", ".join(pool_funcs),
            "score": 0  # Informational - fires on 88% of drivers
        })
    
    return findings


def check_dangerous_operations(imports):
    """Check for dangerous function imports."""
    findings = []
    
    dangerous = {
        "mmmapiospace": ("maps_physical_memory", "MmMapIoSpace - maps physical memory to virtual", 15),
        "zwmapviewofsection": ("maps_memory_section", "ZwMapViewOfSection - maps memory sections", 10),
        "mmmaplockedpageswithreservedmapping": ("maps_locked_pages", "Maps locked pages", 10),
        "mmmaplockedpagesspecifycache": ("maps_locked_pages_cache", "Maps locked pages with cache", 10),
        "rtlcopymemory": ("memcpy_present", "RtlCopyMemory - potential overflow if sizes unchecked", 5),
        "memcpy": ("memcpy_present", "memcpy - potential overflow if sizes unchecked", 5),
        "memmove": ("memmove_present", "memmove present", 3),
        "obreferenceobjectbyname": ("object_reference", "Can reference arbitrary kernel objects", 10),
        # Physical/MDL (from HolyGrail)
        "mmgetphysicaladdress": ("maps_physical_memory", "MmGetPhysicalAddress - translates virtual to physical", 15),
        "mmcopymemory": ("maps_physical_memory", "MmCopyMemory - copies physical/virtual memory", 15),
        "mmcopyvirtualmemory": ("maps_memory_section", "MmCopyVirtualMemory - cross-process memory copy", 10),
        "mmallocatepagesformdl": ("maps_locked_pages", "MmAllocatePagesForMdl - allocates physical pages", 10),
        "ioallocatemdl": ("maps_locked_pages", "IoAllocateMdl - allocates MDL for DMA/mapping", 10),
        # Section/VM (from HolyGrail)
        "zwopensection": ("maps_memory_section", "ZwOpenSection - opens named section object", 10),
        "zwreadvirtualmemory": ("maps_memory_section", "ZwReadVirtualMemory - reads another process memory", 10),
        "zwwritevirtualmemory": ("maps_memory_section", "ZwWriteVirtualMemory - writes another process memory", 10),
        # Process (from HolyGrail)
        "kestackattachprocess": ("maps_memory_section", "KeStackAttachProcess - attaches to another process address space", 10),
        "mmgetsystemroutineaddress": ("dynamic_resolve", "Dynamically resolves kernel functions", 0),  # 66% fire rate
        "zwcreatefile": ("file_operations", "Can create/open files from kernel", 5),
        "zwwritefile": ("file_write", "Can write files from kernel", 5),
        "zwreadfile": ("file_read", "Can read files from kernel", 5),
        "iowmiregistrationcontrol": ("wmi_provider", "WMI provider - additional attack surface", 0),  # 64% fire rate
    }
    
    for func_name, (check_id, detail, _default_score) in dangerous.items():
        if func_name in imports:
            findings.append({
                "check": check_id,
                "detail": detail,
                "score": get_weight(check_id)
            })
    
    return findings


def check_byovd_potential(imports):
    """Check for BYOVD process killer capability."""
    findings = []
    
    # Process handle acquisition
    openers = {"zwopenprocess", "ntopenprocess", "obopenobjectbypointer", "pslookupprocessbyprocessid"}
    # Process termination
    terminators = {"zwterminateprocess", "ntterminateprocess"}
    
    has_opener = bool(imports & openers)
    has_terminator = bool(imports & terminators)
    
    if has_opener and has_terminator:
        opener_names = [i for i in imports if i in openers]
        terminator_names = [i for i in imports if i in terminators]
        findings.append({
            "check": "byovd_process_killer",
            "detail": "BYOVD candidate: has %s + %s (can open and kill processes)" % (
                ", ".join(opener_names), ", ".join(terminator_names)),
            "score": get_weight("byovd_process_killer")
        })
    
    return findings


def check_physical_memory(imports):
    """Check for physical memory R/W capability."""
    findings = []
    
    phys_indicators = {
        "mmmapiospace", "zwmapviewofsection", "mmmaplockedpagesspecifycache",
        "zwopensection",
    }
    
    found = imports & phys_indicators
    if len(found) >= 2:
        findings.append({
            "check": "physical_memory_rw",
            "detail": "Multiple physical memory mapping imports: %s" % ", ".join(found),
            "score": get_weight("physical_memory_rw")
        })
    
    return findings


def check_msr_access(program):
    """Check for MSR read/write instructions in code (rdmsr/wrmsr)."""
    findings = []
    listing = program.getListing()
    func_mgr = program.getFunctionManager()
    
    rdmsr_count = 0
    wrmsr_count = 0
    
    for func in func_mgr.getFunctions(True):
        body = func.getBody()
        inst_iter = listing.getInstructions(body, True)
        while inst_iter.hasNext():
            inst = inst_iter.next()
            mnemonic = inst.getMnemonicString().lower()
            if mnemonic == "rdmsr":
                rdmsr_count += 1
            elif mnemonic == "wrmsr":
                wrmsr_count += 1
    
    if wrmsr_count > 0:
        findings.append({
            "check": "msr_write",
            "detail": "Contains %d WRMSR instruction(s) - can write MSR registers (LSTAR hijack for kernel code exec)" % wrmsr_count,
            "score": get_weight("msr_write")
        })
    
    if rdmsr_count > 0:
        findings.append({
            "check": "msr_read",
            "detail": "Contains %d RDMSR instruction(s) - can read MSR registers (KASLR defeat via LSTAR leak)" % rdmsr_count,
            "score": get_weight("msr_read")
        })
    
    return findings


def check_cr_access(program):
    """Check for control register manipulation (mov cr0/cr4)."""
    findings = []
    listing = program.getListing()
    func_mgr = program.getFunctionManager()
    
    cr_writes = []
    
    for func in func_mgr.getFunctions(True):
        body = func.getBody()
        inst_iter = listing.getInstructions(body, True)
        while inst_iter.hasNext():
            inst = inst_iter.next()
            mnemonic = inst.getMnemonicString().lower()
            if mnemonic == "mov":
                op_str = inst.toString().lower()
                if "cr0" in op_str or "cr4" in op_str:
                    cr_writes.append(op_str.strip())
    
    if cr_writes:
        findings.append({
            "check": "control_register_access",
            "detail": "Control register manipulation (%d instances) - can disable SMEP/WP: %s" % (
                len(cr_writes), ", ".join(cr_writes[:3])),
            "score": get_weight("control_register_access")
        })
    
    return findings


def check_token_steal(imports):
    """Check for token stealing / EPROCESS manipulation primitives."""
    findings = []
    
    process_lookup = {"pslookupprocessbyprocessid", "psreferenceprimarytoken",
                      "zwopenprocesstokenex", "ntopenprocesstoken"}
    found = imports & process_lookup
    
    if len(found) >= 2:
        findings.append({
            "check": "token_steal_primitives",
            "detail": "Token stealing imports: %s (EPROCESS manipulation / LPE)" % ", ".join(found),
            "score": get_weight("token_steal_primitives")
        })
    elif "pslookupprocessbyprocessid" in imports:
        findings.append({
            "check": "process_lookup",
            "detail": "PsLookupProcessByProcessId present (process enumeration capability)",
            "score": get_weight("process_lookup")
        })
    
    return findings


def check_winio_codebase(strings):
    """Detect WinIO/WinRing0 repackaged codebase - known vulnerable."""
    findings = []
    
    winio_indicators = ["winio", "winring0", "winio_mapphystolin",
                        "\\device\\winio", "\\dosdevices\\winring0"]
    
    for s in strings:
        s_lower = s.lower()
        for indicator in winio_indicators:
            if indicator in s_lower:
                findings.append({
                    "check": "winio_codebase",
                    "detail": "WinIO/WinRing0 codebase detected (%s) - known vulnerable driver family (MSR+PhysMem+StackOverflow)" % s[:60],
                    "score": get_weight("winio_codebase")
                })
                return findings
    
    return findings


def check_dse_bypass(strings):
    """Check for Driver Signature Enforcement bypass indicators."""
    findings = []
    
    dse_indicators = ["ci.dll", "g_cioptions", "civalidateimageheader", "ciinitialize"]
    
    for s in strings:
        s_lower = s.lower()
        for indicator in dse_indicators:
            if indicator in s_lower:
                findings.append({
                    "check": "dse_bypass_indicator",
                    "detail": "DSE bypass string: %s (can disable driver signature enforcement)" % s[:60],
                    "score": get_weight("dse_bypass_indicator")
                })
                return findings
    
    return findings


def check_firmware_access(imports, strings):
    """Check for firmware/SPI flash access capability."""
    findings = []
    
    fw_imports = {"halgetbusdatabyoffset", "halsetbusdatabyoffset"}
    found = imports & fw_imports
    
    if found:
        findings.append({
            "check": "firmware_bus_access",
            "detail": "HAL bus data access: %s (firmware/SPI/SMBus interaction)" % ", ".join(found),
            "score": get_weight("firmware_bus_access")
        })
    
    # firmware_string removed - fires on 83% of drivers (too noisy)
    # Only the import-based firmware_bus_access check remains (2% fire rate)
    
    return findings


def check_disk_access(strings):
    """Check for raw disk/partition access capability."""
    findings = []
    
    disk_indicators = ["\\device\\harddisk", "physicaldrive", "rawdisk",
                       "\\device\\physicalmemory"]
    
    for s in strings:
        s_lower = s.lower()
        for indicator in disk_indicators:
            if indicator in s_lower:
                findings.append({
                    "check": "raw_disk_access",
                    "detail": "Raw disk/memory access: %s (wiper/rootkit capability)" % s[:60],
                    "score": get_weight("raw_disk_access")
                })
                return findings
    
    return findings


def check_registry_kernel(imports):
    """Check for kernel-mode registry manipulation."""
    findings = []
    
    reg_funcs = {"zwcreatekey", "zwsetvaluekey", "zwopenkey", "zwdeletekey",
                 "zwenumeratekey", "zwenumeratevaluekey"}
    found = imports & reg_funcs
    
    write_funcs = found & {"zwcreatekey", "zwsetvaluekey", "zwdeletekey"}
    if write_funcs:
        findings.append({
            "check": "kernel_registry_write",
            "detail": "Kernel registry write: %s (persistence vector)" % ", ".join(write_funcs),
            "score": get_weight("kernel_registry_write")
        })
    
    return findings


def check_irp_forwarding(imports):
    """Check for IRP forwarding to other drivers (expanded attack surface)."""
    findings = []
    
    if "iofcalldriver" in imports or "iocalldriver" in imports:
        findings.append({
            "check": "irp_forwarding",
            "detail": "Forwards IRPs to other drivers (IoCallDriver/IofCallDriver) - expanded attack surface",
            "score": 0  # Informational - fires on 58% of drivers
        })
    
    return findings


def check_thin_driver(program, imports):
    """Small drivers with IOCTLs = thin wrapper, likely minimal validation."""
    findings = []
    
    code_size = program.getMemory().getSize()
    has_irp = "iofcompleterequest" in imports or "iocompleterequest" in imports
    func_count = program.getFunctionManager().getFunctionCount()
    
    if has_irp and code_size < 8192:  # < 8KB
        findings.append({
            "check": "thin_driver_critical",
            "detail": "Very small driver (%d bytes) with IRP handling and only %d functions - minimal validation likely" % (code_size, func_count),
            "score": get_weight("thin_driver_critical")
        })
    elif has_irp and code_size < 16384:  # < 16KB
        findings.append({
            "check": "thin_driver",
            "detail": "Small driver (%d bytes) with IRP handling and %d functions - limited room for validation" % (code_size, func_count),
            "score": get_weight("thin_driver")
        })
    
    return findings


def check_unchecked_copy(imports, program):
    """Detect memcpy/RtlCopyMemory near IOCTL handling without size validation.
    
    Heuristic: if driver imports copy functions + IRP handling but no
    ProbeForRead/ProbeForWrite and no ExAllocatePoolWithQuotaTag (size-checked alloc),
    the copy sizes are likely user-controlled.
    """
    findings = []
    
    copy_funcs = {"rtlcopymemory", "memcpy", "memmove", "rtlmovememory"}
    has_copy = bool(imports & copy_funcs)
    has_irp = "iofcompleterequest" in imports or "iocompleterequest" in imports
    has_probe = "probeforread" in imports or "probeforwrite" in imports
    has_quota_alloc = "exallocatepoolwithquotatag" in imports
    
    if has_copy and has_irp and not has_probe and not has_quota_alloc:
        copy_names = [i for i in imports if i in copy_funcs]
        findings.append({
            "check": "unchecked_copy",
            "detail": "CRITICAL: %s with IRP handling but no ProbeFor*/quota alloc - user-controlled sizes likely" % ", ".join(copy_names),
            "score": get_weight("unchecked_copy")
        })
    elif has_copy and has_irp and not has_probe:
        copy_names = [i for i in imports if i in copy_funcs]
        findings.append({
            "check": "weak_copy_validation",
            "detail": "%s with IRP handling, no ProbeFor* (has quota alloc) - partial validation" % ", ".join(copy_names),
            "score": get_weight("weak_copy_validation")
        })
    
    return findings


def check_internal_validation(imports):
    """Detect drivers with internal object validation (false positive reducer).
    
    Drivers that import linked-list and object validation functions are more
    likely to have proper input validation, reducing exploitability.
    """
    findings = []
    
    validation_indicators = {
        "exinterlockedinserthead", "exinterlockedinserttail",
        "exinterlockedremovehead", "initializelisthead",
        "rtlvalidateheap", "exacquirefastmutex",
        "obreferenceobjectbyhandle", "obdereferenceobject",
    }
    
    found = imports & validation_indicators
    if len(found) >= 3:
        findings.append({
            "check": "has_internal_validation",
            "detail": "Driver has internal object validation (%s) - may reduce exploitability" % ", ".join(list(found)[:4]),
            "score": get_weight("has_internal_validation")  # Negative score = reduces overall risk
        })
    
    return findings


# --- Vendor / driver class context checks ---

def load_cna_vendors():
    """Load CNA vendor data from cna_vendors.json."""
    candidates = []
    
    try:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(sourceFile.getAbsolutePath())), "cna_vendors.json"))
    except:
        pass
    
    try:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "cna_vendors.json"))
    except:
        pass
    
    try:
        from ghidra.app.script import GhidraScriptUtil
        for d in GhidraScriptUtil.getScriptDirectories():
            candidates.append(os.path.join(d.getAbsolutePath(), "cna_vendors.json"))
    except:
        pass
    
    candidates.append(os.path.join(os.getcwd(), "cna_vendors.json"))
    
    env_path = os.environ.get("CTHAEH_CNA_PATH")
    if env_path:
        candidates.insert(0, env_path)
    
    for cna_path in candidates:
        try:
            with open(cna_path, "r") as f:
                data = json.load(f)
                vendors = data.get("vendors", {})
                if vendors:
                    print("cna_vendors.json loaded from: %s (%d vendors)" % (cna_path, len(vendors)))
                    return vendors
        except:
            continue
    
    print("WARNING: cna_vendors.json not found, using built-in CNA data")
    return None


CNA_VENDORS_DATA = load_cna_vendors()

# Fallback built-in data (used if cna_vendors.json not found)
CNA_BOUNTY_VENDORS = {
    "qualcomm": {"cna": True, "bounty": True},
    "broadcom": {"cna": True, "bounty": True},
    "intel": {"cna": True, "bounty": True},
    "samsung": {"cna": True, "bounty": True},
    "mediatek": {"cna": True, "bounty": True},
    "nvidia": {"cna": True, "bounty": True},
    "amd": {"cna": True, "bounty": False},
    "asus": {"cna": True, "bounty": False},
    "lenovo": {"cna": True, "bounty": False},
    "dell": {"cna": True, "bounty": False},
    "hp": {"cna": True, "bounty": False},
}

# Driver name patterns for WiFi drivers (massive attack surface, historically rich in vulns)
WIFI_DRIVER_PATTERNS = [
    "wifi", "wlan", "atheros", "athw", "ath6", "ath1",
    "bcmwl", "bcm43", "rtlwlan", "rtwlan", "rtl8",
    "mtkwl", "mt76", "qcwlan", "qcalwifi",
    "nwifi", "netwlan", "iwl", "iwifi",
    "brcmfmac", "brcmsmac",
]

# Audio driver patterns (typically low attack surface, flag low)
AUDIO_DRIVER_PATTERNS = [
    "realtek", "rtkvhd", "rtkaudibus", "portcls",
    "hdaudio", "hdaud", "vstxraul", "vsfx",
    "nahimic", "avolute", "dtsapo", "synaudio",
    "maxxaudio", "dolbyapo",
]

# Windows inbox driver patterns (well-audited, lower priority)
# NOTE: These must match the FULL driver name or start, not substrings.
# "acpi" was removed because it false-matches vendor ACPI drivers like AsusWmiAcpi.
INBOX_DRIVER_PATTERNS = [
    "ntfs", "ndis", "tcpip", "http", "fltmgr",
    "volmgr", "storport", "pci",
    "wdf01000", "ksecdd", "cng",
]


def extract_company_name(strings):
    """Extract actual CompanyName from version info strings."""
    company = None
    for i, s in enumerate(strings):
        s_lower = s.lower()
        if "companyname" in s_lower:
            # CompanyName is often the next string, or embedded in the same one
            # Try to extract the value after "CompanyName"
            parts = s.split("CompanyName")
            if len(parts) > 1 and len(parts[1].strip()) > 2:
                company = parts[1].strip().strip("\x00").strip()
            elif i + 1 < len(strings) and len(strings[i + 1].strip()) > 2:
                company = strings[i + 1].strip()
            break
    return company


# Map known driver name prefixes to vendors (higher priority than string search)
DRIVER_VENDOR_MAP = {
    "nvpcf": "nvidia", "nvraid": "nvidia", "nvlddmkm": "nvidia", "nvstor": "nvidia",
    "nvaudio": "nvidia", "nvhda": "nvidia",
    "amd": "amd", "atikmdag": "amd", "atikmpag": "amd",
    "asus": "asus", "asussaio": "asus",
    "ssud": "samsung",
    "bcmwl": "broadcom", "bcm43": "broadcom",
    "igdkmd": "intel", "iaxnvme": "intel", "iastor": "intel", "iaxhci": "intel",
    "qc": "qualcomm", "qcwlan": "qualcomm",
    "mtk": "mediatek", "mtkwl": "mediatek",
    "len": "lenovo", "lnvhswfx": "lenovo",
    "hp": "hp", "hpqkb": "hp",
    "dell": "dell",
    "athw": "qualcomm", "atheros": "qualcomm", "ath6": "qualcomm",
}


def _match_vendor_from_json(driver_lower, company_lower, all_text_lower):
    """Match vendor using cna_vendors.json data. Returns (vendor_key, vendor_data) or None."""
    if not CNA_VENDORS_DATA:
        return None
    
    # 1. Driver name prefix match (most reliable)
    for vendor_key, vdata in CNA_VENDORS_DATA.items():
        for pattern in vdata.get("driver_patterns", []):
            if driver_lower.startswith(pattern):
                return (vendor_key, vdata)
    
    # 2. CompanyName match
    if company_lower:
        for vendor_key, vdata in CNA_VENDORS_DATA.items():
            for name in vdata.get("names", []):
                if name.lower() in company_lower or company_lower in name.lower():
                    return (vendor_key, vdata)
    
    # 3. Fallback: all strings
    if all_text_lower:
        for vendor_key, vdata in CNA_VENDORS_DATA.items():
            for name in vdata.get("names", []):
                if name.lower() in all_text_lower:
                    return (vendor_key, vdata)
    
    return None


def check_vendor_context(strings, driver_name):
    """Score based on vendor CNA status and bounty availability.
    
    Priority: driver name prefix > CompanyName string > all strings.
    Prevents false vendor attribution (e.g., nvpcf.sys matched 'amd').
    Uses cna_vendors.json if available, falls back to built-in data.
    """
    findings = []
    driver_lower = driver_name.lower().replace(".sys", "")
    company = extract_company_name(strings)
    company_lower = company.lower() if company else ""
    all_text_lower = " ".join(strings).lower()
    
    matched_vendor = None
    bounty_url = None
    
    # Try JSON-based matching first
    json_match = _match_vendor_from_json(driver_lower, company_lower, all_text_lower)
    if json_match:
        vendor_key, vdata = json_match
        is_cna = vdata.get("is_cna", False)
        bounty_url = vdata.get("bounty_url")
        has_bounty = bounty_url is not None and bounty_url != ""
        matched_vendor = (vendor_key, {"cna": is_cna, "bounty": has_bounty})
    
    # Fallback to built-in data
    if not matched_vendor:
        # 1. Driver name prefix
        for prefix in sorted(DRIVER_VENDOR_MAP.keys(), key=len, reverse=True):
            if driver_lower.startswith(prefix):
                vendor_key = DRIVER_VENDOR_MAP[prefix]
                if vendor_key in CNA_BOUNTY_VENDORS:
                    matched_vendor = (vendor_key, CNA_BOUNTY_VENDORS[vendor_key])
                break
        
        # 2. CompanyName
        if not matched_vendor and company_lower:
            for vendor in sorted(CNA_BOUNTY_VENDORS.keys()):
                if vendor in company_lower:
                    matched_vendor = (vendor, CNA_BOUNTY_VENDORS[vendor])
                    break
        
        # 3. All strings
        if not matched_vendor:
            for vendor in sorted(CNA_BOUNTY_VENDORS.keys()):
                if vendor in all_text_lower:
                    matched_vendor = (vendor, CNA_BOUNTY_VENDORS[vendor])
                    break
    
    if matched_vendor:
        vendor_name, info = matched_vendor
        if info["cna"] and info["bounty"]:
            detail = "Vendor %s is CNA with bounty program" % vendor_name.title()
            if bounty_url:
                detail += " (%s)" % bounty_url
            findings.append({
                "check": "vendor_cna_bounty",
                "detail": detail,
                "score": get_weight("vendor_cna_bounty"),
                "vendor_cna": True,
                "vendor_name": vendor_name.title(),
                "bounty_url": bounty_url,
            })
        elif info["cna"]:
            findings.append({
                "check": "vendor_cna",
                "detail": "Vendor %s is CNA (easier CVE assignment path)" % vendor_name.title(),
                "score": get_weight("vendor_cna"),
                "vendor_cna": True,
                "vendor_name": vendor_name.title(),
                "bounty_url": None,
            })
        else:
            findings.append({
                "check": "vendor_not_cna",
                "detail": "Vendor %s is not a CNA (CVE assignment through other channels)" % vendor_name.title(),
                "score": 0,
                "vendor_cna": False,
                "vendor_name": vendor_name.title(),
                "bounty_url": bounty_url if info.get("bounty") else None,
            })
    
    return findings


def check_driver_class(strings, driver_name):
    """Classify driver type and adjust score accordingly."""
    findings = []
    driver_lower = driver_name.lower()
    
    # WiFi drivers - massive IOCTL/WDI surface, historically vuln-rich
    for pattern in WIFI_DRIVER_PATTERNS:
        if pattern in driver_lower:
            findings.append({
                "check": "wifi_driver",
                "detail": "WiFi driver (matched '%s') - massive IOCTL/WDI attack surface, historically rich in vulns" % pattern,
                "score": get_weight("wifi_driver")
            })
            return findings
    
    # Audio drivers - typically tiny IOCTL surface, low priority
    for pattern in AUDIO_DRIVER_PATTERNS:
        if driver_lower.startswith(pattern):
            findings.append({
                "check": "audio_class_driver",
                "detail": "Audio class driver (matched '%s') - typically minimal IOCTL attack surface" % pattern,
                "score": get_weight("audio_class_driver")
            })
            return findings
    
    # Windows inbox drivers - well-audited by Microsoft
    # Use startswith to avoid false matches (e.g. "acpi" in "AsusWmiAcpi")
    for pattern in INBOX_DRIVER_PATTERNS:
        if driver_lower.startswith(pattern):
            findings.append({
                "check": "windows_inbox_driver",
                "detail": "Windows inbox driver (matched '%s') - well-audited by Microsoft" % pattern,
                "score": get_weight("windows_inbox_driver")
            })
            return findings
    
    return findings


def check_large_ioctl_surface(program):
    """Detect drivers with many distinct IOCTL codes (large attack surface).
    
    Uses reachability heuristic: only counts IOCTL codes that appear in
    CMP/SUB/AND/TEST instructions (likely dispatch switch cases) rather
    than all constants that look like IOCTLs.
    """
    findings = []
    listing = program.getListing()
    func_mgr = program.getFunctionManager()
    
    ioctl_codes_all = set()
    ioctl_codes_dispatched = set()
    
    # Instructions that indicate an IOCTL is being compared/dispatched
    DISPATCH_MNEMONICS = {"cmp", "sub", "and", "test", "xor", "je", "jne", "jz", "jnz"}
    
    for func in func_mgr.getFunctions(True):
        body = func.getBody()
        inst_iter = listing.getInstructions(body, True)
        while inst_iter.hasNext():
            inst = inst_iter.next()
            mnemonic = inst.getMnemonicString().lower()
            for i in range(inst.getNumOperands()):
                try:
                    scalar = inst.getScalar(i)
                    if scalar is None:
                        continue
                    val = scalar.getUnsignedValue()
                    # IOCTL codes: DeviceType(16) | Access(2) | Function(12) | Method(2)
                    if val > 0x10000 and val < 0xFFFFFFFF:
                        device_type = (val >> 16) & 0xFFFF
                        # Valid device types: <0x100 (MS defined) or >=0x8000 (vendor)
                        if device_type < 0x100 or device_type >= 0x8000:
                            ioctl_codes_all.add(val)
                            if mnemonic in DISPATCH_MNEMONICS:
                                ioctl_codes_dispatched.add(val)
                except:
                    pass
    
    # Use dispatched count for scoring (more accurate), report both
    dispatched = len(ioctl_codes_dispatched)
    total = len(ioctl_codes_all)
    
    if dispatched > 50:
        findings.append({
            "check": "massive_ioctl_surface",
            "detail": "Massive IOCTL surface: %d dispatched / %d total codes detected" % (dispatched, total),
            "score": get_weight("massive_ioctl_surface")
        })
    elif dispatched > 25:
        findings.append({
            "check": "large_ioctl_surface",
            "detail": "Large IOCTL surface: %d dispatched / %d total codes detected" % (dispatched, total),
            "score": get_weight("large_ioctl_surface")
        })
    elif dispatched > 10:
        findings.append({
            "check": "moderate_ioctl_surface",
            "detail": "Moderate IOCTL surface: %d dispatched / %d total codes detected" % (dispatched, total),
            "score": get_weight("moderate_ioctl_surface")
        })
    elif total > 10 and dispatched <= 10:
        findings.append({
            "check": "ioctl_constants_only",
            "detail": "%d IOCTL-like constants found but only %d in dispatch context (may be internal)" % (total, dispatched),
            "score": 0
        })
    
    return findings


def check_device_interface(strings):
    """Check for device interface GUIDs and named devices."""
    findings = []
    
    for s in strings:
        if "\\Device\\" in s:
            findings.append({
                "check": "named_device",
                "detail": "Creates named device: %s" % s[:80],
                "score": get_weight("named_device")
            })
            break
    
    guid_pattern = re.compile(r'\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}')
    for s in strings:
        if guid_pattern.search(s):
            findings.append({
                "check": "device_interface_guid",
                "detail": "Registers device interface (accessible via SetupDi*)",
                "score": get_weight("device_interface_guid")
            })
            break
    
    return findings


def check_loldrivers(driver_name):
    """Cross-reference against LOLDrivers known-abused list.
    
    Uses a local cache of loldrivers.io data. If not available,
    falls back to driver name matching against known entries.
    """
    findings = []
    driver_lower = driver_name.lower()
    
    # Check local LOLDrivers cache
    cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "loldrivers_cache.json")
    try:
        with open(cache_path, "r") as f:
            lol_data = json.load(f)
            if driver_lower in lol_data:
                entry = lol_data[driver_lower]
                findings.append({
                    "check": "loldrivers_known",
                    "detail": "Listed in LOLDrivers: %s (already documented, skip unless new vuln class)" % entry.get("description", "known vulnerable")[:80],
                    "score": get_weight("loldrivers_known")  # Deprioritize already-documented drivers
                })
                return findings
    except:
        pass
    
    # Fallback: well-known LOLDrivers by name (partial list of most common)
    KNOWN_LOLDRIVERS = {
        "dbutil_2_3.sys": "Dell BIOS utility - CVE-2021-21551",
        "rtcore64.sys": "MSI Afterburner - CVE-2019-16098",
        "gdrv.sys": "GIGABYTE - arbitrary R/W",
        "asio64.sys": "ASRock - arbitrary R/W",
        "aswarpot.sys": "Avast - process killer",
        "procexp152.sys": "Process Explorer - legitimate but abused",
        "cpuz141.sys": "CPU-Z - MSR/PhysMem access",
        "winring0x64.sys": "WinRing0 - MSR/PhysMem/IO",
        "ene.sys": "ENE Technology - arbitrary R/W",
        "asio3.sys": "ASUS AsIO3 - CVE-2025-3464",
        "physmem.sys": "Physical memory access",
        "inpoutx64.sys": "InpOut - port I/O",
        "winio64.sys": "WinIO - port I/O",
        "speedfan.sys": "SpeedFan - MSR/PhysMem",
        "rtkiow8x64.sys": "Realtek I/O - arbitrary R/W",
        "bs_def64.sys": "Biostar - MSR R/W",
        "elrawdsk.sys": "EldoS RawDisk - raw disk access",
    }
    
    if driver_lower in KNOWN_LOLDRIVERS:
        findings.append({
            "check": "loldrivers_known",
            "detail": "Known LOLDriver: %s (already documented, deprioritize)" % KNOWN_LOLDRIVERS[driver_lower],
            "score": get_weight("loldrivers_known")
        })
    
    return findings


def check_symlink_creation(imports, strings):
    """Check for symbolic link creation without ACL.
    
    From research: drivers with IoCreateSymbolicLink + IoCreateDevice (not Secure)
    are directly accessible via \\.\DeviceName from any user. This was the case
    in AsusWmiAcpi (\\.\ATKACPI), MediaTek (\\.\MTKBTFilter), AsIO3.
    """
    findings = []
    
    has_symlink = "iocreatesymboliclink" in imports
    has_create = "iocreatedevice" in imports
    has_secure = "iocreatedevicesecure" in imports
    
    if has_symlink and has_create and not has_secure:
        # Find the device name from strings
        device_names = [s for s in strings if "\\DosDevices\\" in s or "\\Device\\" in s]
        detail = "Symbolic link + IoCreateDevice without IoCreateDeviceSecure"
        if device_names:
            detail += " (%s)" % device_names[0][:60]
        findings.append({
            "check": "symlink_no_acl",
            "detail": detail,
            "score": get_weight("symlink_no_acl")
        })
    
    return findings


def check_auth_bypass_patterns(program, imports):
    """Detect potential auth bypass patterns.
    
    From research:
    - AsIO3: check-after-use (wrmsr executes before validation return)
    - nvpcf: user-controlled byte skips SeTokenIsAdmin check
    - Samsung: no InputBufferLength validation before parsing
    
    Heuristic: drivers that import auth functions but have code paths that
    bypass them. Also detect missing buffer length validation.
    """
    findings = []
    
    # Check for token/SID validation imports (indicates driver TRIES to auth)
    auth_imports = {"setokenisadmin", "zwqueryinformationtoken", "zwopenprocesstokenex",
                    "rtlequalsid", "seaccesscheck"}
    has_auth = bool(imports & auth_imports)
    has_irp = "iofcompleterequest" in imports or "iocompleterequest" in imports
    
    if has_auth and has_irp:
        findings.append({
            "check": "has_auth_checks",
            "detail": "Driver implements auth checks (%s) - verify all IOCTLs are protected" % ", ".join(imports & auth_imports),
            "score": get_weight("has_auth_checks")  # Bonus: auth exists but may be incomplete (like AsusWmiAcpi)
        })
    elif has_irp and not has_auth:
        # No auth at all - more interesting
        findings.append({
            "check": "no_auth_imports",
            "detail": "Driver handles IOCTLs but imports NO authentication functions (no token/SID checks)",
            "score": get_weight("no_auth_imports")
        })
    
    return findings


def check_usb_passthrough(imports, strings):
    """Detect USB request passthrough (like Samsung ssudbus2).
    
    Drivers that forward user-controlled USB control transfers to hardware
    are high-value targets. The Samsung driver allowed arbitrary USB vendor/class
    requests with no validation.
    """
    findings = []
    
    # USB-related imports
    usb_imports = {"usbd_createconfigurationrequestex", "usbd_parseconfigurationdescriptorex",
                   "usbd_getusbdiversion"}
    usb_ioctl_imports = {"iobuilddeviceiocontrolrequest"}
    
    has_usb = bool(imports & usb_imports) or any("usb" in s.lower() for s in strings[:50])
    has_urb_strings = any("urb" in s.lower() or "transferbuffer" in s.lower() for s in strings)
    
    # Check for internal USB submit patterns
    usb_submit_strings = [s for s in strings if "ioctl_internal_usb" in s.lower() or "submit_urb" in s.lower()]
    
    if has_usb and ("iocalldriver" in imports or "iofcalldriver" in imports):
        findings.append({
            "check": "usb_request_forwarding",
            "detail": "USB driver that forwards requests to lower stack (potential USB command passthrough)",
            "score": get_weight("usb_request_forwarding")
        })
    
    return findings


def check_hci_bt_surface(imports, strings):
    """Detect Bluetooth HCI command passthrough (like MediaTek mtkbtfilterx).
    
    BT filter drivers with HCI/WMT command passthrough allow firmware manipulation,
    eFuse access, and arbitrary BT chip control from userspace.
    """
    findings = []
    
    bt_indicators = ["bluetooth", "hci", "btfilter", "mtkbt", "bthusb", "btusb"]
    has_bt = any(ind in s.lower() for s in strings for ind in bt_indicators)
    
    # Crypto imports suggest firmware decryption (like MediaTek)
    crypto_imports = {"bcryptopenprovider", "bcryptdecrypt", "bcryptgeneratesymmetrickey",
                      "bcryptcreatehash", "bcryptfinishhash", "bcrypthashdata",
                      "bcryptopenalgorithmprovider"}
    has_crypto = bool(imports & crypto_imports)
    
    if has_bt:
        detail = "Bluetooth driver"
        if has_crypto:
            detail += " with crypto imports (potential firmware decryption - high-value target)"
            findings.append({
                "check": "bt_driver_crypto",
                "detail": detail,
                "score": get_weight("bt_driver_crypto")
            })
        else:
            findings.append({
                "check": "bt_driver",
                "detail": detail + " (check for HCI/WMT command passthrough)",
                "score": get_weight("bt_driver")
            })
    
    return findings


def check_efuse_access(strings):
    """Detect eFuse read/write capability (like MediaTek).
    
    eFuse access from userspace = permanent hardware modification capability.
    """
    findings = []
    
    efuse_indicators = ["efuse", "e_fuse", "fuse_read", "fuse_write"]
    for s in strings:
        s_lower = s.lower()
        for ind in efuse_indicators:
            if ind in s_lower:
                findings.append({
                    "check": "efuse_access",
                    "detail": "eFuse access detected (%s) - potential permanent hardware modification" % s[:60],
                    "score": get_weight("efuse_access")
                })
                return findings
    
    return findings


def check_acpi_wmi_surface(imports, strings):
    """Detect ACPI/WMI method execution (like AsusWmiAcpi).
    
    Drivers that expose ACPI WMI methods to userspace can allow hardware
    control (fan speed, thermal policy, GPU switching, WiFi toggle).
    """
    findings = []
    
    wmi_imports = {"iowmiopenblock", "iowmiexecutemethod", "iowmiregistrationcontrol"}
    has_wmi_exec = "iowmiexecutemethod" in imports or "iowmiopenblock" in imports
    
    acpi_strings = [s for s in strings if "acpi" in s.lower() or "pnp0c14" in s.lower() or "wmi" in s.lower()]
    
    if has_wmi_exec:
        findings.append({
            "check": "wmi_method_execution",
            "detail": "Executes WMI methods (IoWMIExecuteMethod) - check if user-controlled method IDs",
            "score": get_weight("wmi_method_execution")
        })
    
    if any("\\device\\physicalmemory" in s.lower() for s in strings):
        findings.append({
            "check": "physical_memory_section",
            "detail": "References \\Device\\PhysicalMemory - direct physical memory access primitive",
            "score": get_weight("physical_memory_section")
        })
    
    return findings


def check_port_io(program):
    """Detect IN/OUT port I/O instructions (like AsIO3).
    
    Direct port I/O allows PCI config access (0xCF8/0xCFC), CMOS manipulation,
    and other hardware control. Common in ASUS/MSI utility drivers.
    """
    findings = []
    listing = program.getListing()
    func_mgr = program.getFunctionManager()
    
    in_count = 0
    out_count = 0
    
    for func in func_mgr.getFunctions(True):
        body = func.getBody()
        inst_iter = listing.getInstructions(body, True)
        while inst_iter.hasNext():
            inst = inst_iter.next()
            mnemonic = inst.getMnemonicString().lower()
            if mnemonic in ("in", "inb", "inw", "ind"):
                in_count += 1
            elif mnemonic in ("out", "outb", "outw", "outd"):
                out_count += 1
    
    if in_count > 0 and out_count > 0:
        findings.append({
            "check": "port_io_rw",
            "detail": "Port I/O: %d IN + %d OUT instructions (PCI config, CMOS, hardware control)" % (in_count, out_count),
            "score": get_weight("port_io_rw")
        })
    elif in_count > 0:
        findings.append({
            "check": "port_io_read",
            "detail": "Port I/O read: %d IN instructions" % in_count,
            "score": get_weight("port_io_read")
        })
    
    return findings


def check_cve_history(driver_name, current_year=2026):
    """Check if driver matches a family with known prior CVEs.

    Scores based on:
    - has_prior_cves: driver family has any known CVEs (+15)
    - has_recent_cves_2yr: family has CVEs from last 2 years (+10)

    Returns (findings_list, matched_cves_list) tuple.
    """
    findings = []
    matched_cves = []
    driver_lower = driver_name.lower().replace(".sys", "")

    for family_id, family_data in DRIVER_CVE_FAMILIES.items():
        patterns = family_data.get("patterns", [])
        for pattern in patterns:
            if pattern in driver_lower:
                cves = family_data.get("cves", [])
                if not cves:
                    break
                matched_cves = cves
                vendor = family_data.get("vendor", "Unknown")
                cve_ids = [c["id"] for c in cves]
                findings.append({
                    "check": "has_prior_cves",
                    "detail": "%s family (%s) has %d known CVEs: %s" % (
                        vendor, family_id, len(cves), ", ".join(cve_ids[:5])),
                    "score": get_weight("has_prior_cves")
                })

                recent = [c for c in cves if c.get("year", 0) >= current_year - 2]
                if recent:
                    recent_ids = [c["id"] for c in recent]
                    findings.append({
                        "check": "has_recent_cves_2yr",
                        "detail": "%d recent CVEs (last 2yr): %s" % (len(recent), ", ".join(recent_ids)),
                        "score": get_weight("has_recent_cves_2yr")
                    })
                return findings, matched_cves
        else:
            continue
        break

    return findings, matched_cves


def check_comms_capability(imports):
    """Check for user-mode communication bridge primitives.

    Drivers WITH comms capability are more interesting because they're
    attackable from userspace. Checks for: IoCreateDevice, IoCreateSymbolicLink,
    FltRegisterFilter, FltCreateCommunicationPort, IofCompleteRequest.
    """
    findings = []
    comms_imports = {
        "iocreatedevice", "iocreatesymboliclink", "fltregisterfilter",
        "fltcreatecommunicationport", "iofcompleterequest",
    }
    found = imports & comms_imports
    if len(found) >= 2:
        findings.append({
            "check": "comms_capability",
            "detail": "User-mode comms bridge: %s (attackable from userspace)" % ", ".join(found),
            "score": get_weight("comms_capability"),
        })
    return findings


def check_ppl_killer(imports):
    """Check for PPL killer potential.

    Specific combo: ZwTerminateProcess AND (ZwOpenProcess OR PsLookupProcessByProcessId)
    = can terminate protected processes (AV/EDR/PPL).
    """
    findings = []
    has_terminate = "zwterminateprocess" in imports
    has_open = "zwopenprocess" in imports
    has_lookup = "pslookupprocessbyprocessid" in imports
    if has_terminate and (has_open or has_lookup):
        opener = "ZwOpenProcess" if has_open else "PsLookupProcessByProcessId"
        findings.append({
            "check": "ppl_killer_potential",
            "detail": "PPL killer: ZwTerminateProcess + %s (can terminate protected processes)" % opener,
            "score": get_weight("ppl_killer_potential"),
        })
    return findings


def check_compound_primitives(findings_so_far):
    """Score compound exploit primitives based on combinations.
    
    From research:
    - PhysMem R/W + MSR W = almost certainly exploitable (AsIO3)
    - IOCTL surface + no auth + named device = low-hanging fruit (AsusWmiAcpi, Samsung)
    - USB passthrough + no size validation = pool overflow (Samsung ssudbus2)
    """
    compound_findings = []
    check_names = {f["check"] for f in findings_so_far}
    
    # MSR write + physical memory = god-mode driver
    if "msr_write" in check_names and ("maps_physical_memory" in check_names or "physical_memory_rw" in check_names):
        compound_findings.append({
            "check": "compound_god_mode",
            "detail": "MSR write + physical memory access = full kernel control primitive",
            "score": get_weight("compound_god_mode")
        })
    
    # Named device + no auth + IOCTLs = easy target
    if "named_device" in check_names and "no_auth_imports" in check_names:
        compound_findings.append({
            "check": "compound_easy_target",
            "detail": "Named device with IOCTL surface and no authentication - low-hanging fruit",
            "score": get_weight("compound_easy_target")
        })
    
    # Symlink + insecure creation + FILE_ANY_ACCESS pattern
    if "symlink_no_acl" in check_names and "insecure_device_creation" in check_names:
        compound_findings.append({
            "check": "compound_wide_open",
            "detail": "Symbolic link + insecure device creation = accessible from any user process",
            "score": get_weight("compound_wide_open")
        })
    
    return compound_findings


def check_vuln_pattern_composite(findings_so_far, imports):
    """Composite check derived from Jeff's 8 confirmed vulns.
    
    The pattern: IOCTL surface + dangerous primitive + missing validation.
    This was the exact pattern in:
    - Samsung ssudbus2: IOCTLs + USB passthrough + no input length checks
    - ASUS AsusWmiAcpi: IOCTLs + WMI exec + missing auth on some codes
    - ASUS AsIO3: IOCTLs + MSR/PhysMem + check-after-use auth bypass
    - MediaTek mtkbtfilterx: IOCTLs + HCI passthrough + no validation
    """
    findings = []
    check_names = {f["check"] for f in findings_so_far}
    
    has_ioctl = "has_ioctl_handler" in check_names or "named_device" in check_names
    has_dangerous = bool(check_names & {
        "msr_write", "msr_read", "physical_memory_rw", "maps_physical_memory",
        "port_io_rw", "wmi_method_execution", "usb_request_forwarding",
        "bt_driver_crypto", "physical_memory_section", "byovd_process_killer",
        "unchecked_copy", "efuse_access"
    })
    lacks_validation = bool(check_names & {
        "no_probe_functions", "no_auth_imports", "symlink_no_acl",
        "insecure_device_creation"
    })
    
    if has_ioctl and has_dangerous and lacks_validation:
        findings.append({
            "check": "vuln_pattern_composite",
            "detail": "Matches confirmed vuln pattern: IOCTL surface + dangerous primitive + weak/no validation",
            "score": get_weight("vuln_pattern_composite")
        })
    
    return findings


def check_wdf_vs_wdm(imports, strings):
    """Detect WDF vs WDM driver framework and adjust scoring.
    
    From research: nvpcf.sys (WDF) scored 200+ but was FP because WDF device 
    interfaces inherit SDDL security descriptors that block non-admin access,
    even without explicit auth checks in driver code.
    
    WDM drivers using IoCreateDevice (not Secure) are higher risk because
    they rely on default DACLs that allow any local user access.
    """
    findings = []
    
    # WDF indicators
    wdf_imports = {"wdfversionbind", "wdfversionunbind", "wdfversionbindclass",
                   "wdfdrivercreate", "wdfdevicecreate", "wdfdevicecreatedeviceinterface"}
    has_wdf = bool(imports & wdf_imports)
    
    # Also check strings for WDF patterns
    if not has_wdf:
        has_wdf = any("wdf" in s.lower() and ("driver" in s.lower() or "device" in s.lower()) for s in strings[:100])
    
    # Device interface (WDF typically uses these, which have SDDL security)
    has_device_interface = any("deviceinterface" in s.lower() or 
                               "{" in s and "}" in s and "-" in s  # GUID pattern
                               for s in strings[:200])
    
    has_create_device = "iocreatedevice" in imports
    has_create_secure = "iocreatedevicesecure" in imports
    
    if has_wdf and has_device_interface:
        findings.append({
            "check": "wdf_device_interface",
            "detail": "WDF driver with device interface (likely SDDL-protected, harder to access from unprivileged user)",
            "score": get_weight("wdf_device_interface")
        })
    elif has_create_device and not has_create_secure and not has_wdf:
        findings.append({
            "check": "wdm_direct_device",
            "detail": "WDM driver using IoCreateDevice (default DACL, easier user-mode access)",
            "score": get_weight("wdm_direct_device")
        })
    
    return findings


def check_uefi_access(imports):
    """Detect UEFI variable access capability.
    
    From research: MediaTek mtkbtfilterx imports ExGetFirmwareEnvironmentVariable.
    UEFI variable access from a driver can enable Secure Boot manipulation,
    firmware persistence, and boot configuration changes.
    """
    findings = []
    
    uefi_imports = {"exgetfirmwareenvironmentvariable", "exsetfirmwareenvironmentvariable",
                    "zwquerysystemenvironmentvalue", "zwsetsystemenvironmentvalue",
                    "zwquerysystemenvironmentvalueex", "zwsetsystemenvironmentvalueex"}
    found = imports & uefi_imports
    
    if found:
        has_write = bool(found & {"exsetfirmwareenvironmentvariable", 
                                   "zwsetsystemenvironmentvalue",
                                   "zwsetsystemenvironmentvalueex"})
        if has_write:
            findings.append({
                "check": "uefi_variable_access",
                "detail": "UEFI variable WRITE capability: %s (firmware persistence, Secure Boot manipulation)" % ", ".join(found),
                "score": get_weight("uefi_variable_access") + 5  # Extra for write
            })
        else:
            findings.append({
                "check": "uefi_variable_access",
                "detail": "UEFI variable read: %s (can read firmware config, boot variables)" % ", ".join(found),
                "score": get_weight("uefi_variable_access")
            })
    
    return findings


def check_hardcoded_crypto(strings):
    """Detect hardcoded cryptographic keys or seeds.
    
    From research: MediaTek mtkbtfilterx uses hardcoded SHA1 seed for
    AES-128 key derivation to decrypt firmware. Hardcoded crypto material
    means firmware decryption can be replicated, enabling malicious firmware injection.
    """
    findings = []
    
    # Look for crypto-related strings that suggest hardcoded key material
    crypto_indicators = ["aes", "sha1", "sha256", "hmac", "decrypt", "encrypt",
                         "gen_key", "key_deriv", "hardcoded", "secret"]
    
    # Long hex strings that look like keys (32+ hex chars)
    import re
    hex_key_pattern = re.compile(r'[0-9a-fA-F]{32,}')
    
    key_strings = []
    for s in strings:
        s_lower = s.lower()
        # Function names suggesting key generation
        if any(ind in s_lower for ind in ["gen_key", "genkey", "key_gen", "keygen", 
                                           "decrypt_file", "decryptfile", "init_key"]):
            key_strings.append(s[:60])
        # Long hex strings (potential embedded keys)
        if hex_key_pattern.search(s) and len(s) > 32 and len(s) < 128:
            key_strings.append(s[:60])
    
    if key_strings:
        findings.append({
            "check": "hardcoded_crypto_key",
            "detail": "Potential hardcoded crypto material: %s (firmware decryption key recovery)" % "; ".join(key_strings[:3]),
            "score": get_weight("hardcoded_crypto_key")
        })
    
    return findings


def check_urb_construction(imports, strings):
    """Detect USB Request Block (URB) construction from user input.
    
    From research: Samsung ssudbus2 builds URBs directly from user-supplied 
    IOCTL input data. TransferBufferLength set from user-controlled wLength
    without validation against SystemBuffer size = pool overflow.
    
    Pattern: USB driver + IRP handling + internal USB IOCTLs = URB passthrough.
    """
    findings = []
    
    # USB submission imports
    usb_submit = {"usbd_createconfigurationrequestex", "usbd_selectconfigurb",
                  "usbd_createhandle"}
    internal_usb = any("ioctl_internal_usb" in s.lower() for s in strings)
    
    has_irp = "iofcompleterequest" in imports or "iocompleterequest" in imports
    has_usb = bool(imports & usb_submit) or internal_usb
    
    # URB-related strings
    urb_strings = [s for s in strings if "urb" in s.lower() and 
                   any(x in s.lower() for x in ["transfer", "buffer", "control", "vendor", "class"])]
    
    if has_usb and has_irp and ("iocalldriver" in imports or "iofcalldriver" in imports):
        detail = "USB driver builds URBs and forwards to lower stack"
        if urb_strings:
            detail += " (URB strings: %s)" % "; ".join(urb_strings[:2])
        findings.append({
            "check": "urb_from_user_input",
            "detail": detail,
            "score": get_weight("urb_from_user_input")
        })
    
    # HCI command passthrough (BT-specific, from MediaTek research)
    hci_strings = [s for s in strings if "hci" in s.lower() and 
                   any(x in s.lower() for x in ["cmd", "command", "send", "handler"])]
    if hci_strings and has_irp:
        findings.append({
            "check": "hci_command_passthrough",
            "detail": "HCI command passthrough detected: %s (raw BT hardware control from userspace)" % "; ".join(hci_strings[:2]),
            "score": get_weight("hci_command_passthrough")
        })
    
    return findings


def check_driver_class_ranking(imports, import_dlls=None):
    """Classify driver by type based on Ghidra symbol table imports.

    Returns findings with driver_class info and scoring for dangerous classes.
    CRITICAL/HIGH class drivers get +10 (dangerous_driver_class).
    """
    findings = []
    if import_dlls is None:
        import_dlls = set()

    has_iocreatedevice = "iocreatedevice" in imports
    has_wdfdrivercreate = "wdfdrivercreate" in imports
    has_fltregisterfilter = "fltregisterfilter" in imports

    cls = "UNKNOWN"
    category = "Unclassified"

    # CRITICAL: FS filter or raw WDM
    if has_fltregisterfilter:
        cls = "CRITICAL"
        category = "File system filter"
    elif has_iocreatedevice and not has_wdfdrivercreate:
        cls = "CRITICAL"
        category = "Raw WDM driver"

    # HIGH: NDIS, Bluetooth, USB function
    if cls == "UNKNOWN":
        ndis = {"ndisregisterprotocoldriver", "ndismregisterminiportdriver"}
        if imports & ndis:
            cls = "HIGH"
            category = "NDIS network driver"

    if cls == "UNKNOWN":
        bt_dlls = {"bthport.sys", "bthhfp.sys"}
        if import_dlls & bt_dlls:
            cls = "HIGH"
            category = "Bluetooth driver"

    if cls == "UNKNOWN":
        usb = {"usbd_createconfigurationrequestex",
               "wdfusbtargetdevicesendcontroltransfersynchronously"}
        if imports & usb:
            cls = "HIGH"
            category = "USB function driver"

    # MEDIUM: WDF/KMDF, display
    if cls == "UNKNOWN":
        if has_wdfdrivercreate:
            cls = "MEDIUM"
            category = "WDF/KMDF driver"

    if cls == "UNKNOWN":
        if "dxgkinitialize" in imports:
            cls = "MEDIUM"
            category = "Display/GPU driver"

    # LOW: audio, HID, printer
    if cls == "UNKNOWN":
        audio = {"portclscreate", "pcregistersubdevice"}
        if imports & audio:
            cls = "LOW"
            category = "Audio (PortCls) driver"

    if cls == "UNKNOWN":
        if "hidregisterminidriver" in imports:
            cls = "LOW"
            category = "HID minidriver"

    if cls != "UNKNOWN":
        score = 0
        if cls in ("CRITICAL", "HIGH"):
            score = get_weight("dangerous_driver_class")
        findings.append({
            "check": "dangerous_driver_class" if score > 0 else "driver_class_info",
            "detail": "Driver class: %s (%s)" % (cls, category),
            "score": score,
            "driver_class": cls,
            "driver_category": category,
        })
    else:
        findings.append({
            "check": "driver_class_info",
            "detail": "Driver class: UNKNOWN (unclassified)",
            "score": 0,
            "driver_class": "UNKNOWN",
            "driver_category": "Unclassified",
        })

    return findings


def check_whql_inbox(strings, driver_name):
    """Detect WHQL-signed or Windows inbox drivers for stronger deprioritization.
    
    Microsoft-signed inbox drivers have lower base rates of exploitable vulns.
    Stronger penalty than the basic inbox pattern check.
    """
    findings = []
    
    # Check for Microsoft as CompanyName (inbox driver)
    company = extract_company_name(strings)
    if company and "microsoft" in company.lower():
        findings.append({
            "check": "whql_signed_inbox",
            "detail": "Microsoft-signed inbox driver (%s) - well-audited, lower priority" % company[:60],
            "score": get_weight("whql_signed_inbox")
        })
    
    return findings


def check_hvci_compat(imports):
    """Check if driver is HVCI compatible."""
    findings = []
    
    if "mmmapiospace" in imports:
        findings.append({
            "check": "likely_hvci_incompatible",
            "detail": "Uses MmMapIoSpace (often HVCI incompatible)",
            "score": get_weight("likely_hvci_incompatible")
        })
    
    return findings


# =============================================================================
# v7: AwesomeMalDevLinks-inspired checks (GitHub issues #7-#12)
# =============================================================================

def check_memory_corruption_patterns(imports, program):
    """Detect UAF, double-free, and free-without-null patterns (#7).
    
    References:
    - https://whiteknightlabs.com/2025/06/03/understanding-use-after-free-uaf-in-windows-kernel-drivers/
    - https://whiteknightlabs.com/2025/06/10/understanding-double-free-in-windows-kernel-drivers/
    """
    findings = []
    
    free_funcs = ["exfreepoolwithtag", "exfreepool", "exfreepoolwithtagnx", "exfreepool2"]
    deref_funcs = ["obdereferenceobject", "obdereferenceobjectwithag", "obdereferenceobjectdeferdelete"]
    
    has_free = any(f in imports for f in free_funcs)
    has_deref = any(f in imports for f in deref_funcs)
    has_ioctl = "iofcompleterequestex" in imports or "wdfrequestcomplete" in imports or "iocompleterequestex" in imports
    
    # Check for free functions in IOCTL dispatch context
    if has_free and has_ioctl:
        # Look for free-then-use patterns via instruction analysis
        try:
            listing = program.getListing()
            func_mgr = program.getFunctionManager()
            free_call_count = 0
            
            for func in func_mgr.getFunctions(True):
                func_name = func.getName().lower()
                # Focus on dispatch/IOCTL handler functions
                if not any(kw in func_name for kw in ["dispatch", "ioctl", "internal", "device_control", "irp"]):
                    continue
                
                insn_iter = listing.getInstructions(func.getBody(), True)
                free_seen = False
                insn_after_free = 0
                
                while insn_iter.hasNext():
                    insn = insn_iter.next()
                    mnemonic = insn.getMnemonicString().lower()
                    
                    if mnemonic == "call":
                        ref_str = str(insn)
                        ref_lower = ref_str.lower()
                        if any(f in ref_lower for f in free_funcs):
                            free_seen = True
                            insn_after_free = 0
                            free_call_count += 1
                        elif free_seen and insn_after_free < 10:
                            # Another call shortly after free = potential UAF
                            if any(f in ref_lower for f in free_funcs):
                                findings.append({
                                    "check": "double_free_indicator",
                                    "detail": "Consecutive pool free calls in %s (potential double-free)" % func.getName(),
                                    "score": get_weight("double_free_indicator"),
                                })
                                free_seen = False
                    
                    if free_seen:
                        insn_after_free += 1
                        # Check for dereference after free (MOV from freed region)
                        if insn_after_free > 2 and insn_after_free < 15:
                            if mnemonic in ["mov", "lea"] and "rax" in str(insn).lower():
                                # Heuristic: memory access after free
                                pass  # Tracked by free_call_count
                        if insn_after_free > 20:
                            free_seen = False
            
            if free_call_count >= 3:
                findings.append({
                    "check": "uaf_indicator",
                    "detail": "Multiple pool free calls in IOCTL dispatch paths (%d occurrences)" % free_call_count,
                    "score": get_weight("uaf_indicator"),
                })
            elif free_call_count >= 1:
                findings.append({
                    "check": "free_without_null",
                    "detail": "Pool free in IOCTL path without obvious pointer nullification",
                    "score": get_weight("free_without_null"),
                })
        except Exception:
            # Fallback: just flag the import combination
            if has_free:
                findings.append({
                    "check": "free_without_null",
                    "detail": "Pool free functions present with IOCTL handling (review for UAF)",
                    "score": get_weight("free_without_null"),
                })
    
    # Heavy ObDereferenceObject usage
    if has_deref:
        deref_count = sum(1 for f in deref_funcs if f in imports)
        if deref_count >= 2:
            findings.append({
                "check": "ob_deref_heavy",
                "detail": "Multiple ObDereferenceObject variants imported (%d)" % deref_count,
                "score": get_weight("ob_deref_heavy"),
            })
    
    return findings


def check_byovd_primitives(imports, program):
    """Expanded BYOVD exploitation primitive detection (#9).
    
    References:
    - https://github.com/BlackSnufkin/BYOVD
    - https://github.com/0xJs/BYOVD_read_write_primitive
    - https://github.com/TheCruZ/kdmapper
    """
    findings = []
    
    has_map_io = "mmmapiospace" in imports or "mmmapiospaceex" in imports
    has_map_locked = "mmmaplockedpages" in imports or "mmmaplockedpageswithreservedmapping" in imports or "mmmaplockedpagesspecifycache" in imports
    has_ioctl = "iofcompleterequestex" in imports or "iocompleterequestex" in imports
    has_device = "iocreatedevice" in imports or "iocreatesymboliclink" in imports
    
    # Arbitrary kernel read: MmMapIoSpace in driver with IOCTL handling + device
    if has_map_io and has_ioctl and has_device:
        findings.append({
            "check": "byovd_arb_read",
            "detail": "MmMapIoSpace + IOCTL handler + named device (potential arbitrary kernel read primitive)",
            "score": get_weight("byovd_arb_read"),
        })
        
        # If also has write capability
        has_write = "mmunmapiospace" in imports or "rtlcopymemory" in imports or "memmove" in imports or "memcpy" in imports
        if has_write:
            findings.append({
                "check": "byovd_arb_write",
                "detail": "MmMapIoSpace + copy/write + IOCTL (potential arbitrary kernel write primitive)",
                "score": get_weight("byovd_arb_write"),
            })
    
    # Kernel execute: queue work items or APCs from user-controlled data
    execute_apis = ["keinsertqueueapc", "exqueueworkitem", "pscreatesystemthread", "keinsertqueuedpc"]
    has_execute = any(api in imports for api in execute_apis)
    if has_execute and has_ioctl:
        findings.append({
            "check": "byovd_kernel_execute",
            "detail": "Kernel execution APIs (%s) with IOCTL handler" % ", ".join(
                api for api in execute_apis if api in imports
            ),
            "score": get_weight("byovd_kernel_execute"),
        })
    
    # PID-based process termination
    has_open_process = "zwopenprocess" in imports or "ntopenprocess" in imports
    has_terminate = "zwterminateprocess" in imports or "ntterminateprocess" in imports
    if has_open_process and has_terminate:
        findings.append({
            "check": "byovd_pid_terminate",
            "detail": "ZwOpenProcess + ZwTerminateProcess (PID-based process killer primitive)",
            "score": get_weight("byovd_pid_terminate"),
        })
    
    return findings


def check_ioring_surface(imports, strings):
    """Detect IORING attack surface (#10).
    
    Reference: https://knifecoat.com/Posts/Arbitrary+Kernel+RW+using+IORING's
    """
    findings = []
    
    ioring_apis = ["iocreatefileex", "iocreatefilespecifydeviceobjecthint", "ntcreateioring",
                   "ntsubmitioring", "ntqueryioring", "ntcloseioring"]
    ioring_strings_pattern = ["ioring", "io_ring", "iouring"]
    
    has_ioring_api = any(api in imports for api in ioring_apis)
    has_ioring_str = any(
        any(pat in s.lower() for pat in ioring_strings_pattern)
        for s in strings
    )
    
    # Shared memory section creation without validation
    has_shared_mem = ("zwcreatesection" in imports or "ntcreatesection" in imports) and \
                     ("zwmapviewofsection" in imports or "ntmapviewofsection" in imports)
    
    if has_ioring_api or has_ioring_str:
        findings.append({
            "check": "ioring_surface",
            "detail": "IORING-related APIs or strings detected (novel kernel attack surface)",
            "score": get_weight("ioring_surface"),
        })
    elif has_shared_mem and ("iocreatefileex" in imports):
        findings.append({
            "check": "ioring_surface",
            "detail": "Section creation + IoCreateFileEx (IORING-adjacent shared memory pattern)",
            "score": get_weight("ioring_surface"),
        })
    
    return findings


def check_killer_driver(imports, strings):
    """Detect EDR/AV killer driver patterns (#11).
    
    References:
    - https://whiteknightlabs.com/2025/10/28/methodology-of-reversing-vulnerable-killer-drivers/
    - https://research.checkpoint.com/2025/large-scale-exploitation-of-legacy-driver/
    """
    findings = []
    
    # Process enumeration + termination combo
    has_enum = "zwquerysysteminformation" in imports or "ntquerysysteminformation" in imports
    has_terminate = "zwterminateprocess" in imports or "ntterminateprocess" in imports
    has_open = "zwopenprocess" in imports or "ntopenprocess" in imports
    
    if has_enum and (has_terminate or has_open):
        findings.append({
            "check": "killer_enum_terminate",
            "detail": "Process enumeration + termination APIs (ZwQuerySystemInformation + ZwTerminateProcess/ZwOpenProcess)",
            "score": get_weight("killer_enum_terminate"),
        })
    
    # Service control from kernel (very unusual)
    scm_apis = ["openscmanagerw", "openscmanagera", "controlservice", "deleteservice",
                "openservicew", "openservicea", "changeserviceconfig"]
    has_scm = any(api in imports for api in scm_apis)
    if has_scm:
        findings.append({
            "check": "killer_service_control",
            "detail": "SCM APIs imported (%s)" % ", ".join(api for api in scm_apis if api in imports),
            "score": get_weight("killer_service_control"),
        })
    
    # Callback removal
    callback_remove_apis = ["pssetcreateprocessnotifyroutine", "pssetcreateprocessnotifyroutineex",
                            "pssetcreateprocessnotifyroutineex2", "obunregistercallbacks",
                            "pssetcreatethreadnotifyroutine", "pssetloadimagenotifyroutine",
                            "cmunregistercallback"]
    has_callback_remove = any(api in imports for api in callback_remove_apis)
    if has_callback_remove:
        findings.append({
            "check": "killer_callback_removal",
            "detail": "Kernel callback registration/removal APIs (%s)" % ", ".join(
                api for api in callback_remove_apis if api in imports
            ),
            "score": get_weight("killer_callback_removal"),
        })
    
    # Minifilter unload
    minifilter_apis = ["fltunregisterfilter", "filterunload", "fltclosecommunicationport"]
    has_minifilter = any(api in imports for api in minifilter_apis)
    if has_minifilter:
        findings.append({
            "check": "killer_minifilter_unload",
            "detail": "Minifilter unload APIs present (%s)" % ", ".join(
                api for api in minifilter_apis if api in imports
            ),
            "score": get_weight("killer_minifilter_unload"),
        })
    
    # EDR product name strings
    edr_names = ["defender", "crowdstrike", "csfalcon", "sentinel", "sentinelone",
                 "carbonblack", "carbon black", "cylance", "sophos", "bitdefender",
                 "kaspersky", "eset", "trendmicro", "trend micro", "mcafee",
                 "symantec", "norton", "malwarebytes", "webroot", "panda",
                 "avast", "avg", "fortinet", "fireeye", "mandiant"]
    
    found_edr = []
    strings_lower = [s.lower() for s in strings[:2000]]  # Limit for performance
    for edr in edr_names:
        if any(edr in s for s in strings_lower):
            found_edr.append(edr)
    
    if len(found_edr) >= 2:
        findings.append({
            "check": "killer_edr_strings",
            "detail": "Multiple EDR/AV product names in strings: %s" % ", ".join(found_edr[:10]),
            "score": get_weight("killer_edr_strings"),
        })
    
    return findings


def check_bloatware_oem(strings, driver_name):
    """Detect bloatware/OEM utility drivers (#12).
    
    References:
    - https://github.com/sensepost/bloatware-pwn/tree/main/razerpwn
    - https://mrbruh.com/asusdriverhub/
    """
    findings = []
    
    # Known bloatware-heavy OEM vendors (ASUS already covered by vendor_context)
    oem_vendors = {
        "razer": "Razer",
        "msi": "MSI",
        "gigabyte": "Gigabyte",
        "asrock": "ASRock",
        "corsair": "Corsair",
        "nzxt": "NZXT",
        "alienware": "Alienware",
        "steelseries": "SteelSeries",
        "roccat": "ROCCAT",
        "thermaltake": "Thermaltake",
        "evga": "EVGA",
        "aorus": "AORUS",
    }
    
    driver_lower = driver_name.lower()
    all_text = " ".join(strings[:500]).lower()
    
    for key, name in oem_vendors.items():
        if key in driver_lower or key in all_text:
            findings.append({
                "check": "oem_bloatware_vendor",
                "detail": "OEM bloatware vendor detected: %s (consumer utility drivers often lack security review)" % name,
                "score": get_weight("oem_bloatware_vendor"),
            })
            break
    
    # Utility driver string patterns
    utility_patterns = ["rgb", "overclock", "fan control", "fan speed", "led control",
                        "hotkey", "system monitor", "hardware monitor", "hwmonitor",
                        "game mode", "lighting", "chroma", "aura sync", "mystic light",
                        "dragon center", "armory crate", "synapse", "icue"]
    
    found_utility = []
    for pat in utility_patterns:
        if pat in all_text:
            found_utility.append(pat)
    
    if found_utility:
        findings.append({
            "check": "utility_driver_strings",
            "detail": "Utility/peripheral driver indicators: %s" % ", ".join(found_utility[:5]),
            "score": get_weight("utility_driver_strings"),
        })
    
    # PE timestamp age check (driver age)
    try:
        pe_header = program.getMemory().getBlock(".text")
        # Try to get TimeDateStamp from PE header
        exe_path = program.getExecutablePath()
        # Use program creation date as proxy if available
        creation = program.getCreationDate()
        if creation:
            import java.util.Date as Date
            now = Date()
            age_ms = now.getTime() - creation.getTime()
            age_years = age_ms / (365.25 * 24 * 60 * 60 * 1000)
            if age_years >= 5:
                findings.append({
                    "check": "driver_age_5plus",
                    "detail": "Driver appears to be %.1f years old (older drivers = higher risk)" % age_years,
                    "score": get_weight("driver_age_5plus"),
                })
    except Exception:
        pass  # Age check is best-effort
    
    return findings


def check_candidate_points(program, imports):
    """Kernel Rhabdomancer: per-function dangerous API call mapping with
    call graph proximity to IOCTL dispatch (#13 / Option B).
    
    Inspired by 0xdea/Rhabdomancer.java but adapted for kernel drivers
    and implemented in pure Jython (no decompiler dependency).
    
    Strategy:
    1. Build kernel-specific candidate point tiers (dangerous APIs)
    2. Walk every function, find CALL instructions to dangerous APIs
    3. Identify IOCTL dispatch functions via heuristics
    4. Score based on: tier level, proximity to IOCTL path, missing validation
    
    References:
    - https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java
    - https://hnsecurity.it/blog/automating-binary-vulnerability-discovery-with-ghidra-and-semgrep/
    """
    findings = []
    
    # --- Kernel candidate point tiers ---
    # Tier 0: Critical - direct exploitation primitives
    TIER0 = {
        "mmmapiospace": "MmMapIoSpace (physical memory mapping)",
        "mmmapiospaceex": "MmMapIoSpaceEx (physical memory mapping)",
        "mmmaplockedpagesspecifycache": "MmMapLockedPagesSpecifyCache (locked pages to user)",
        "mmmaplockedpages": "MmMapLockedPages (locked pages mapping)",
        "zwmapviewofsection": "ZwMapViewOfSection (section mapping)",
        "ntmapviewofsection": "NtMapViewOfSection (section mapping)",
        "rtlcopymemory": "RtlCopyMemory (kernel memcpy)",
        "memmove": "memmove (memory copy)",
        "memcpy": "memcpy (memory copy)",
        "zwterminateprocess": "ZwTerminateProcess (process kill)",
        "ntterminateprocess": "NtTerminateProcess (process kill)",
        "keinsertqueueapc": "KeInsertQueueApc (APC injection)",
        "exqueueworkitem": "ExQueueWorkItem (kernel work item)",
        "zwwritefile": "ZwWriteFile (kernel file write)",
        "ntwritefile": "NtWriteFile (kernel file write)",
        "wrmsr": "WRMSR (MSR write)",
    }
    
    # Tier 1: Interesting - often part of exploit chains
    TIER1 = {
        "exallocatepool": "ExAllocatePool (deprecated, no tag)",
        "exallocatepoolwithtag": "ExAllocatePoolWithTag",
        "exallocatepool2": "ExAllocatePool2",
        "obreferenceobjectbyhandle": "ObReferenceObjectByHandle",
        "zwopenprocess": "ZwOpenProcess",
        "ntopenprocess": "NtOpenProcess",
        "zwcreatesection": "ZwCreateSection",
        "iocreatedevice": "IoCreateDevice",
        "iocreatesymboliclink": "IoCreateSymbolicLink",
        "exfreepoolwithtag": "ExFreePoolWithTag",
        "exfreepool": "ExFreePool",
        "obdereferenceobject": "ObDereferenceObject",
        "zwsetvaluekey": "ZwSetValueKey (registry write)",
        "zwcreatefile": "ZwCreateFile",
        "rdmsr": "RDMSR (MSR read)",
    }
    
    # Tier 2: Review - context-dependent
    TIER2 = {
        "kestackattachprocess": "KeStackAttachProcess",
        "iogetdeviceobjectpointer": "IoGetDeviceObjectPointer",
        "zwquerysysteminformation": "ZwQuerySystemInformation",
        "ntquerysysteminformation": "NtQuerySystemInformation",
        "pslookupprocessbyprocessid": "PsLookupProcessByProcessId",
        "mmgetsystemroutineaddress": "MmGetSystemRoutineAddress",
        "zwloaddriver": "ZwLoadDriver",
        "zwunloaddriver": "ZwUnloadDriver",
        "iocreatefile": "IoCreateFile",
        "iocalldriver": "IoCallDriver (IRP forwarding)",
    }
    
    # Validation functions (their presence near dangerous calls = safer)
    VALIDATION_FUNCS = {
        "probeforread", "probeforwrite", "mmprobeandlockpages",
        "exgetpreviousmode", "sestatus", "ioverifyirpstacklocation",
    }
    
    # --- Step 1: Identify IOCTL dispatch functions ---
    # Heuristic: functions with multiple IOCTL-like constants in CMP instructions
    listing = program.getListing()
    func_mgr = program.getFunctionManager()
    
    ioctl_dispatch_funcs = set()  # function entry addresses
    all_func_names = {}  # addr -> name mapping
    
    for func in func_mgr.getFunctions(True):
        fname = func.getName().lower()
        all_func_names[func.getEntryPoint().toString()] = func.getName()
        
        # Name-based heuristic
        if any(kw in fname for kw in ["dispatch", "ioctl", "devicecontrol", "device_control", "irp_mj"]):
            ioctl_dispatch_funcs.add(func.getEntryPoint().toString())
            continue
        
        # Constant-based heuristic: count IOCTL-shaped constants in CMP/SUB
        try:
            body = func.getBody()
            inst_iter = listing.getInstructions(body, True)
            ioctl_consts = 0
            while inst_iter.hasNext():
                insn = inst_iter.next()
                mnemonic = insn.getMnemonicString().lower()
                if mnemonic in ("cmp", "sub"):
                    for i in range(insn.getNumOperands()):
                        try:
                            val = insn.getScalar(i)
                            if val is not None:
                                v = val.getUnsignedValue()
                                # IOCTL codes: bits 16-31 = device type, bits 2-13 = function
                                if 0x220000 <= v <= 0x2F0FFF or 0x80000 <= v <= 0x8F0FFF:
                                    ioctl_consts += 1
                        except:
                            pass
            if ioctl_consts >= 2:
                ioctl_dispatch_funcs.add(func.getEntryPoint().toString())
        except:
            pass
    
    # --- Step 2: Build call-from-dispatch set (1 level deep) ---
    dispatch_callees = set()  # functions called from IOCTL dispatch
    for func in func_mgr.getFunctions(True):
        if func.getEntryPoint().toString() in ioctl_dispatch_funcs:
            try:
                for callee in func.getCalledFunctions(None):
                    dispatch_callees.add(callee.getEntryPoint().toString())
            except:
                pass
    
    # --- Step 3: Walk all functions, find candidate points ---
    candidate_points = []  # list of {func, api, tier, in_ioctl_path, has_validation}
    
    # Build a set of all dangerous API names (lowercased) for fast lookup
    all_dangerous = {}
    for api, desc in TIER0.items():
        all_dangerous[api] = (0, desc)
    for api, desc in TIER1.items():
        all_dangerous[api] = (1, desc)
    for api, desc in TIER2.items():
        all_dangerous[api] = (2, desc)
    
    for func in func_mgr.getFunctions(True):
        func_addr = func.getEntryPoint().toString()
        func_name = func.getName()
        
        # Skip thunks and tiny functions
        try:
            if func.isThunk():
                continue
            body = func.getBody()
            if body.getNumAddresses() < 8:
                continue
        except:
            continue
        
        # Determine if this function is in the IOCTL path
        is_dispatch = func_addr in ioctl_dispatch_funcs
        is_dispatch_callee = func_addr in dispatch_callees
        in_ioctl_path = is_dispatch or is_dispatch_callee
        
        # Scan for validation functions in this function
        has_validation = False
        dangerous_calls = []
        
        try:
            inst_iter = listing.getInstructions(body, True)
            while inst_iter.hasNext():
                insn = inst_iter.next()
                mnemonic = insn.getMnemonicString().lower()
                
                if mnemonic == "call":
                    insn_str = str(insn).lower()
                    
                    # Check for validation
                    for vfunc in VALIDATION_FUNCS:
                        if vfunc in insn_str:
                            has_validation = True
                    
                    # Check for dangerous APIs
                    for api, (tier, desc) in all_dangerous.items():
                        if api in insn_str:
                            dangerous_calls.append({
                                "api": api,
                                "desc": desc,
                                "tier": tier,
                                "address": insn.getAddress().toString(),
                            })
        except:
            continue
        
        for call in dangerous_calls:
            candidate_points.append({
                "func": func_name,
                "func_addr": func_addr,
                "api": call["api"],
                "desc": call["desc"],
                "tier": call["tier"],
                "address": call["address"],
                "in_ioctl_path": in_ioctl_path,
                "has_validation": has_validation,
            })
    
    # --- Step 4: Score candidate points ---
    tier0_ioctl = []
    tier0_other = []
    tier1_ioctl = []
    no_validation_dangerous = []
    
    for cp in candidate_points:
        if cp["tier"] == 0:
            if cp["in_ioctl_path"]:
                tier0_ioctl.append(cp)
            else:
                tier0_other.append(cp)
        elif cp["tier"] == 1 and cp["in_ioctl_path"]:
            tier1_ioctl.append(cp)
        
        if cp["tier"] <= 1 and cp["in_ioctl_path"] and not cp["has_validation"]:
            no_validation_dangerous.append(cp)
    
    # Generate findings
    if tier0_ioctl:
        # Group by unique APIs for cleaner output
        apis_seen = {}
        for cp in tier0_ioctl:
            key = cp["api"]
            if key not in apis_seen:
                apis_seen[key] = cp
        
        detail_parts = []
        for api, cp in apis_seen.items():
            detail_parts.append("%s in %s @ %s" % (cp["desc"], cp["func"], cp["address"]))
        
        findings.append({
            "check": "candidate_tier0_ioctl",
            "detail": "Critical APIs in IOCTL dispatch path: %s" % "; ".join(detail_parts[:5]),
            "score": get_weight("candidate_tier0_ioctl"),
            "candidate_count": len(tier0_ioctl),
            "candidates": [{"func": cp["func"], "api": cp["api"], "addr": cp["address"]} for cp in tier0_ioctl[:10]],
        })
    
    if tier0_other:
        findings.append({
            "check": "candidate_tier0_other",
            "detail": "Critical APIs outside IOCTL path (%d call sites across %d unique APIs)" % (
                len(tier0_other), len(set(cp["api"] for cp in tier0_other))
            ),
            "score": get_weight("candidate_tier0_other"),
        })
    
    if tier1_ioctl and len(tier1_ioctl) >= 3:
        findings.append({
            "check": "candidate_tier1_ioctl",
            "detail": "Multiple interesting APIs in IOCTL path (%d call sites)" % len(tier1_ioctl),
            "score": get_weight("candidate_tier1_ioctl"),
        })
    
    if no_validation_dangerous:
        apis = set(cp["desc"] for cp in no_validation_dangerous)
        findings.append({
            "check": "candidate_no_validation",
            "detail": "Dangerous APIs in IOCTL path WITHOUT ProbeForRead/Write: %s" % ", ".join(list(apis)[:5]),
            "score": get_weight("candidate_no_validation"),
            "unvalidated_count": len(no_validation_dangerous),
        })
    
    # Summary metadata (always include for reporting, even if score is 0)
    if candidate_points:
        findings.append({
            "check": "candidate_point_summary",
            "detail": "Rhabdomancer: %d candidate points (%d tier0, %d tier1, %d tier2), %d in IOCTL path, %d dispatch funcs identified" % (
                len(candidate_points),
                len([cp for cp in candidate_points if cp["tier"] == 0]),
                len([cp for cp in candidate_points if cp["tier"] == 1]),
                len([cp for cp in candidate_points if cp["tier"] == 2]),
                len([cp for cp in candidate_points if cp["in_ioctl_path"]]),
                len(ioctl_dispatch_funcs),
            ),
            "score": 0,  # Informational
            "total_candidates": len(candidate_points),
            "dispatch_functions": list(ioctl_dispatch_funcs)[:10],
        })
    
    return findings


def get_driver_info(program):
    """Extract basic driver metadata including parsed version info."""
    info = {
        "name": program.getName(),
        "path": program.getExecutablePath(),
        "format": program.getExecutableFormat(),
        "language": str(program.getLanguage()),
        "compiler": str(program.getCompilerSpec()),
        "size": program.getMemory().getSize(),
        "function_count": program.getFunctionManager().getFunctionCount(),
    }
    
    strings = get_strings(program)
    
    # Parse VS_VERSION_INFO fields
    version_fields = {}
    VS_KEYS = ["CompanyName", "FileDescription", "FileVersion", "InternalName",
                "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion"]
    
    for i, s in enumerate(strings):
        for key in VS_KEYS:
            if key in s:
                # Value is often embedded after the key or is the next string
                parts = s.split(key)
                if len(parts) > 1:
                    val = parts[1].strip().strip("\x00").strip()
                    if len(val) > 1:
                        version_fields[key] = val[:100]
                # Also check next string as the value
                if i + 1 < len(strings):
                    next_s = strings[i + 1].strip()
                    if next_s and len(next_s) > 1 and key not in next_s:
                        if key not in version_fields:
                            version_fields[key] = next_s[:100]
    
    if version_fields:
        info["version_info"] = version_fields
        # Set readable summary
        company = version_fields.get("CompanyName", "")
        product = version_fields.get("ProductName", version_fields.get("FileDescription", ""))
        version = version_fields.get("FileVersion", version_fields.get("ProductVersion", ""))
        summary_parts = [p for p in [company, product, version] if p]
        if summary_parts:
            info["version_summary"] = " | ".join(summary_parts)
    
    # Fallback to old method
    if "version_info" not in info:
        for s in strings:
            if "CompanyName" in s or "FileDescription" in s or "ProductName" in s:
                info["version_string"] = s[:200]
                break
    
    return info


def run():
    """Main triage function - the Cthaeh sees all."""
    program = currentProgram
    
    if program is None:
        print("ERROR: No program loaded")
        return
    
    imports = get_imports(program)
    import_dlls = get_import_dlls(program)
    strings = get_strings(program)
    driver_info = get_driver_info(program)
    driver_name = driver_info.get("name", "")
    
    # Check known FP / already-investigated list
    skip_reason = INVESTIGATED.get(driver_name)
    if skip_reason:
        result = {
            "driver": driver_info,
            "score": 0,
            "priority": "INVESTIGATED",
            "skip_reason": skip_reason,
            "findings_count": 0,
            "findings": [{
                "check": "investigated_skip",
                "detail": skip_reason,
                "score": 0
            }],
            "import_count": len(imports),
            "string_count": len(strings),
        }
        print("===TRIAGE_START===")
        print(json.dumps(result, indent=2))
        print("===TRIAGE_END===")
        return
    
    all_findings = []
    all_findings.extend(check_device_creation(imports, strings))
    all_findings.extend(check_ioctl_handling(imports, program))
    all_findings.extend(check_buffer_methods(program))
    all_findings.extend(check_validation(imports))
    all_findings.extend(check_pool_operations(imports))
    all_findings.extend(check_dangerous_operations(imports))
    all_findings.extend(check_byovd_potential(imports))
    all_findings.extend(check_physical_memory(imports))
    all_findings.extend(check_device_interface(strings))
    all_findings.extend(check_hvci_compat(imports))
    # LOLDrivers cross-reference
    all_findings.extend(check_loldrivers(driver_name))
    # v2 checks
    all_findings.extend(check_msr_access(program))
    all_findings.extend(check_cr_access(program))
    all_findings.extend(check_token_steal(imports))
    all_findings.extend(check_winio_codebase(strings))
    all_findings.extend(check_dse_bypass(strings))
    all_findings.extend(check_firmware_access(imports, strings))
    all_findings.extend(check_disk_access(strings))
    all_findings.extend(check_registry_kernel(imports))
    # v3 checks (feedback refinements)
    all_findings.extend(check_irp_forwarding(imports))
    all_findings.extend(check_thin_driver(program, imports))
    all_findings.extend(check_unchecked_copy(imports, program))
    all_findings.extend(check_internal_validation(imports))
    # v3.2 checks (vendor/class context)
    all_findings.extend(check_vendor_context(strings, driver_name))
    all_findings.extend(check_driver_class(strings, driver_name))
    all_findings.extend(check_large_ioctl_surface(program))
    # v4.1 checks (from real vuln research: Samsung, ASUS, MediaTek, NVIDIA)
    all_findings.extend(check_symlink_creation(imports, strings))
    all_findings.extend(check_auth_bypass_patterns(program, imports))
    all_findings.extend(check_usb_passthrough(imports, strings))
    all_findings.extend(check_hci_bt_surface(imports, strings))
    all_findings.extend(check_efuse_access(strings))
    all_findings.extend(check_acpi_wmi_surface(imports, strings))
    all_findings.extend(check_port_io(program))
    # v4.2 checks
    all_findings.extend(check_whql_inbox(strings, driver_name))
    # v4.3 checks (from deep research review: Samsung, MediaTek, NVIDIA FP lesson, PreviousMode blog)
    all_findings.extend(check_wdf_vs_wdm(imports, strings))
    all_findings.extend(check_uefi_access(imports))
    all_findings.extend(check_hardcoded_crypto(strings))
    all_findings.extend(check_urb_construction(imports, strings))
    # v5: driver class ranking
    all_findings.extend(check_driver_class_ranking(imports, import_dlls))
    # v6: HolyGrail-inspired checks
    all_findings.extend(check_comms_capability(imports))
    all_findings.extend(check_ppl_killer(imports))
    # v7: AwesomeMalDevLinks-inspired checks (#7-#12)
    all_findings.extend(check_memory_corruption_patterns(imports, program))
    all_findings.extend(check_byovd_primitives(imports, program))
    all_findings.extend(check_ioring_surface(imports, strings))
    all_findings.extend(check_killer_driver(imports, strings))
    all_findings.extend(check_bloatware_oem(strings, driver_name))
    # v7.1: Kernel Rhabdomancer - candidate point analysis (call graph + per-function API mapping)
    all_findings.extend(check_candidate_points(program, imports))
    # v5: CVE history check
    cve_findings, matched_cves = check_cve_history(driver_name)
    all_findings.extend(cve_findings)
    # Compound scoring (must run last - uses results from above)
    all_findings.extend(check_compound_primitives(all_findings))
    all_findings.extend(check_vuln_pattern_composite(all_findings, imports))
    
    total_score = sum(f["score"] for f in all_findings)
    
    if total_score >= THRESHOLDS["CRITICAL"]:
        priority = "CRITICAL"
    elif total_score >= THRESHOLDS["HIGH"]:
        priority = "HIGH"
    elif total_score >= THRESHOLDS["MEDIUM"]:
        priority = "MEDIUM"
    elif total_score >= THRESHOLDS["LOW"]:
        priority = "LOW"
    else:
        priority = "SKIP"
    
    # Extract vendor CNA info from findings for top-level access
    vendor_info = {}
    for f in all_findings:
        if f.get("vendor_name"):
            vendor_info = {
                "vendor_name": f["vendor_name"],
                "is_cna": f.get("vendor_cna", False),
                "bounty_url": f.get("bounty_url"),
            }
            break
    
    # Extract driver class from findings
    driver_class_info = {"class": "UNKNOWN", "category": "Unclassified"}
    for f in all_findings:
        if "driver_class" in f:
            driver_class_info = {"class": f["driver_class"], "category": f.get("driver_category", "")}
            break

    result = {
        "driver": driver_info,
        "score": total_score,
        "priority": priority,
        "driver_class": driver_class_info,
        "findings_count": len(all_findings),
        "findings": all_findings,
        "import_count": len(imports),
        "string_count": len(strings),
    }
    
    if vendor_info:
        result["vendor_info"] = vendor_info
    
    if matched_cves:
        result["cve_history"] = matched_cves

    print("===TRIAGE_START===")
    print(json.dumps(result, indent=2))
    print("===TRIAGE_END===")


run()
