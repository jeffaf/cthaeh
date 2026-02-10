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

# Ghidra imports (available in Ghidra scripting environment)
from ghidra.program.model.symbol import SourceType
from ghidra.program.util import DefinedDataIterator


def get_imports(program):
    """Get all imported function names."""
    imports = set()
    sym_table = program.getSymbolTable()
    for sym in sym_table.getExternalSymbols():
        imports.add(sym.getName().lower())
    return imports


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
            "score": 15
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
            "score": 10
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
        findings.append({
            "check": "method_neither",
            "detail": "Found %d potential METHOD_NEITHER IOCTLs (raw user pointers)" % method_neither_count,
            "score": 15
        })
    
    if method_buffered_count > 0:
        findings.append({
            "check": "method_buffered",
            "detail": "Found %d potential METHOD_BUFFERED IOCTLs" % method_buffered_count,
            "score": 5
        })
    
    if file_any_access_count > 0:
        findings.append({
            "check": "file_any_access",
            "detail": "Found %d IOCTLs with FILE_ANY_ACCESS (no privilege check)" % file_any_access_count,
            "score": 15
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
            "score": 10
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
                "score": 10
            })
        
        findings.append({
            "check": "has_pool_operations",
            "detail": "Uses pool allocation: %s" % ", ".join(pool_funcs),
            "score": 5
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
        "obregisterobjectbyname": ("object_reference", "Can reference arbitrary kernel objects", 10),
        "mmgetsystemroutineaddress": ("dynamic_resolve", "Dynamically resolves kernel functions", 5),
        "zwcreatefile": ("file_operations", "Can create/open files from kernel", 5),
        "zwwritefile": ("file_write", "Can write files from kernel", 5),
        "zwreadfile": ("file_read", "Can read files from kernel", 5),
        "iowmiregistrationcontrol": ("wmi_provider", "WMI provider - additional attack surface", 5),
    }
    
    for func_name, (check_id, detail, score) in dangerous.items():
        if func_name in imports:
            findings.append({
                "check": check_id,
                "detail": detail,
                "score": score
            })
    
    return findings


def check_byovd_potential(imports):
    """Check for BYOVD process killer capability."""
    findings = []
    
    # Process handle acquisition
    openers = {"zwopenprocess", "ntopenprocess", "obopenaobjectbypointer", "pslookupprocessbyprocessid"}
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
            "score": 20
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
            "score": 15
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
            "score": 25
        })
    
    if rdmsr_count > 0:
        findings.append({
            "check": "msr_read",
            "detail": "Contains %d RDMSR instruction(s) - can read MSR registers (KASLR defeat via LSTAR leak)" % rdmsr_count,
            "score": 15
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
            "score": 20
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
            "score": 15
        })
    elif "pslookupprocessbyprocessid" in imports:
        findings.append({
            "check": "process_lookup",
            "detail": "PsLookupProcessByProcessId present (process enumeration capability)",
            "score": 5
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
                    "score": 25
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
                    "score": 20
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
            "score": 15
        })
    
    fw_strings = ["spi", "bios", "firmware", "smbus", "smbios"]
    for s in strings:
        s_lower = s.lower()
        for fs in fw_strings:
            if fs in s_lower and len(s) < 100:
                findings.append({
                    "check": "firmware_string",
                    "detail": "Firmware-related string: %s" % s[:60],
                    "score": 5
                })
                return findings
    
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
                    "score": 15
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
            "score": 10
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
                "score": 15
            })
            break
    
    guid_pattern = re.compile(r'\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}')
    for s in strings:
        if guid_pattern.search(s):
            findings.append({
                "check": "device_interface_guid",
                "detail": "Registers device interface (accessible via SetupDi*)",
                "score": 5
            })
            break
    
    return findings


def check_hvci_compat(program):
    """Check if driver is HVCI compatible."""
    findings = []
    
    imports = get_imports(program)
    
    if "mmmapiospace" in imports:
        findings.append({
            "check": "likely_hvci_incompatible",
            "detail": "Uses MmMapIoSpace (often HVCI incompatible)",
            "score": 5
        })
    
    return findings


def get_driver_info(program):
    """Extract basic driver metadata."""
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
    strings = get_strings(program)
    driver_info = get_driver_info(program)
    
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
    all_findings.extend(check_hvci_compat(program))
    # New checks (v2)
    all_findings.extend(check_msr_access(program))
    all_findings.extend(check_cr_access(program))
    all_findings.extend(check_token_steal(imports))
    all_findings.extend(check_winio_codebase(strings))
    all_findings.extend(check_dse_bypass(strings))
    all_findings.extend(check_firmware_access(imports, strings))
    all_findings.extend(check_disk_access(strings))
    all_findings.extend(check_registry_kernel(imports))
    
    total_score = sum(f["score"] for f in all_findings)
    
    if total_score >= 120:
        priority = "CRITICAL"
    elif total_score >= 80:
        priority = "HIGH"
    elif total_score >= 50:
        priority = "MEDIUM"
    elif total_score >= 25:
        priority = "LOW"
    else:
        priority = "SKIP"
    
    result = {
        "driver": driver_info,
        "score": total_score,
        "priority": priority,
        "findings_count": len(all_findings),
        "findings": all_findings,
        "import_count": len(imports),
        "string_count": len(strings),
    }
    
    print("===TRIAGE_START===")
    print(json.dumps(result, indent=2))
    print("===TRIAGE_END===")


run()
