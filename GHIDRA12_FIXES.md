# Cthaeh — Ghidra 12 Compatibility Fixes

## Problem

Running `run_triage.py` against any driver produced `FAILED (no triage output)` for every driver. Root cause: two separate incompatibilities with Ghidra 12.

---

## Fix 1: Use `pyghidraRun` instead of `analyzeHeadless` (`run_triage.py`)

### Why

Ghidra 12 removed built-in Python (Jython) from `analyzeHeadless`. Python scripts now require PyGhidra, which is launched via `pyghidraRun`. Running a `.py` script through the old `analyzeHeadless` binary produces:

```
GhidraScriptLoadException: Ghidra was not started with PyGhidra. Python is not available
```

### What changed

**`run_ghidra_analysis()`** — replaced `analyzeHeadless`/`analyzeHeadless.bat` with `pyghidraRun`/`pyghidraRun.bat`, and added `--headless` as the first argument to the command (required by `pyghidraRun` to enable headless mode). The Ghidra install dir is **not** passed as an extra argument — `pyghidraRun` is a shell script that already knows its own install location.

Before:
```python
if sys.platform == "win32":
    headless = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
else:
    headless = os.path.join(ghidra_path, "support", "analyzeHeadless")

cmd = [headless, project_dir, f"triage_{driver_name}", "-import", ...]
```

After:
```python
if sys.platform == "win32":
    headless = os.path.join(ghidra_path, "support", "pyghidraRun.bat")
else:
    headless = os.path.join(ghidra_path, "support", "pyghidraRun")

cmd = [headless, "--headless", project_dir, f"triage_{driver_name}", "-import", ...]
```

The same change was applied in **`main()`** where the Ghidra path is validated on startup.

---

## Fix 2: Replace `DefinedDataIterator.definedStrings()` (`driver_triage.py`)

### Why

`DefinedDataIterator.definedStrings()` was removed from the Ghidra 12 API. Calling it raised:

```
AttributeError: type object 'ghidra.program.util.DefinedDataIterator' has no attribute 'definedStrings'
```

### What changed

**`get_strings()`** — replaced the removed API with an equivalent using `Listing.getDefinedData()`, filtering results by mnemonic string (the same method used internally by Ghidra 12's own example scripts).

Before:
```python
from ghidra.program.util import DefinedDataIterator

def get_strings(program):
    strings = []
    for data in DefinedDataIterator.definedStrings(program):
        val = data.getDefaultValueRepresentation()
        if val:
            strings.append(val.strip('"').strip("'"))
    return strings
```

After:
```python
_STRING_MNEMONICS = {"ds", "unicode", "p_unicode", "p_string", "p_string255", "mbcs"}

def get_strings(program):
    strings = []
    listing = program.getListing()
    data_iter = listing.getDefinedData(program.getMinAddress(), True)
    while data_iter.hasNext():
        data = data_iter.next()
        if data.getMnemonicString() in _STRING_MNEMONICS:
            val = data.getDefaultValueRepresentation()
            if val:
                strings.append(val.strip('"').strip("'"))
    return strings
```

The `DefinedDataIterator` import was also removed as it is no longer used.
