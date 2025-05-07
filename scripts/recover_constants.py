from ida_imports import *
from pathlib import Path
import time


ida_idaapi.require("utils")
ida_idaapi.require("recover_modules")
ida_idaapi.require("parse_module_constants")


def force_load_constants(module_data):
    """Load module constants by force using Appcall"""
    loadConstantsBlob = ida_idd.Appcall["loadConstantsBlob"]
    for module_name, (mod_consts_rva, module_name_ea_rva) in module_data.items():
        # Convert RVA to absolute addresses
        mod_consts = mod_consts_rva + ida_nalt.get_imagebase()
        module_name_ea = module_name_ea_rva + ida_nalt.get_imagebase()
        
        # Skip main module
        if module_name == "__main__":
            continue

        # Validate addresses
        if mod_consts == 0 or module_name_ea == 0:
            ida_kernwin.msg(f"[!] Invalid address for {module_name}, skipping.\n")
            continue

        ida_kernwin.msg(f"Loading constants for {module_name} at {hex(mod_consts)}, name at {hex(module_name_ea)}...\n")
        try:
            loadConstantsBlob(0, mod_consts, module_name_ea)
        except Exception as e:
            ida_kernwin.msg(f"[!] Appcall failed for {module_name}: {e}\n")
            continue

        # Appcall sometimes needs a small delay
        time.sleep(2)

    # Refresh memory view after all appcalls
    ida_dbg.refresh_debugger_memory()
    ida_kernwin.msg("\n")


def parse_all_constants(module_data, log_file="constants.log"):  
    """Recover loaded constants in all modules & log them"""
    # Reset log file
    try:
        Path(log_file).unlink()
    except FileNotFoundError:
        pass

    with open(log_file, "a") as f:
        for module_name, (mod_consts_rva, _) in module_data.items():
            f.write(f"{'-'*30} [modulecode_{module_name}] {'-'*30}\n")
            mod_consts = mod_consts_rva + ida_nalt.get_imagebase()
            try:
                constants = parse_module_constants.parse_module_constants(mod_consts)
                for constant in constants:
                    f.write(f"{constant}\n")
            except Exception as e:
                ida_kernwin.msg(f"[ERROR] Failed to recover constants for {module_name} ({hex(mod_consts)}): {e}\n")
            f.write("\n")
        
        
def recover_constants():
    # Recover modules data
    main_ea = recover_modules.find_entry_point()  # modulecode___main__
    if main_ea is None:
        ida_kernwin.msg("[!] Entry point not found. Aborting.\n")
        return

    module_data = recover_modules.find_custom_modules()

    # Set breakpoint at entry and start debugger
    ida_dbg.add_bpt(main_ea)
    utils.start_debugger()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)

    # Force-load constants and parse them
    force_load_constants(module_data)
    parse_all_constants(module_data)

    # Clean up debugger and breakpoint
    utils.stop_debugger()
    ida_dbg.del_bpt(main_ea)
    ida_auto.auto_wait()


if __name__ == "__main__":
    ida_kernwin.msg_clear()
    recover_constants()
