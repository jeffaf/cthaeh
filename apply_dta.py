# apply_dta.py - Ghidra Pre-Script: Load Talos Windows Driver Data Type Archive
#
# Loads the Cisco Talos .gdt archive into the current program's data type manager
# so that Windows kernel types (IRP, IO_STACK_LOCATION, DEVICE_OBJECT, etc.) are
# available during analysis.
#
# Usage: analyzeHeadless ... -preScript apply_dta.py
#
# Source: https://github.com/Cisco-Talos/Windows-drivers-GDT-file
#
# NOTE: This is Jython (Python 2). No f-strings. Use % formatting.
#
# @category Security
# @author Jeff Barron

import os

from ghidra.program.model.data import FileDataTypeManager
from java.io import File


def find_gdt():
    """Find the .gdt file relative to this script's location."""
    # Try relative to script directory first
    script_dir = os.path.dirname(sourceFile.getAbsolutePath())
    candidates = [
        os.path.join(script_dir, "data", "windows_driver_types.gdt"),
        os.path.join(script_dir, "windows_driver_types.gdt"),
    ]

    # Also check CTHAEH_DTA_PATH env var
    env_path = os.environ.get("CTHAEH_DTA_PATH", "")
    if env_path:
        candidates.insert(0, env_path)

    for path in candidates:
        if os.path.isfile(path):
            return path

    return None


def apply_dta():
    """Load the .gdt archive into the current program's data type manager."""
    gdt_path = find_gdt()

    if gdt_path is None:
        println("[apply_dta] WARNING: No .gdt file found. Skipping DTA import.")
        println("[apply_dta]   Run: python Cthaeh.py setup")
        println("[apply_dta]   Or set CTHAEH_DTA_PATH environment variable.")
        return

    println("[apply_dta] Loading DTA: %s" % gdt_path)

    gdt_file = File(gdt_path)
    archive = FileDataTypeManager.openFileArchive(gdt_file, False)

    try:
        dtm = currentProgram.getDataTypeManager()
        source_dtm = archive.getDataTypeManager()

        count = 0
        txn = dtm.startTransaction("Import Talos DTA")
        try:
            for dt in source_dtm.getAllDataTypes():
                name = dt.getName()
                # Skip built-in types that Ghidra already has
                path = dt.getCategoryPath().getPath()
                if path.startswith("/BuiltInTypes"):
                    continue
                dtm.addDataType(dt, None)
                count += 1
        finally:
            dtm.endTransaction(txn, True)

        println("[apply_dta] Imported %d data types from Talos archive." % count)

    finally:
        archive.close()


# Entry point
apply_dta()
