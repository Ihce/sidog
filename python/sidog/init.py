
import sys, ctypes, json, pathlib

_libname = {"linux": "libsidog.so",
            "darwin": "libsidog.dylib",
            "win32": "sidog.dll"}[sys.platform]

_lib = ctypes.CDLL(str(pathlib.Path(__file__).with_name(_libname)))

_DisBytes = _lib.DisassembleBytes
_DisBytes.argtypes = [
    ctypes.c_void_p, ctypes.c_int,
    ctypes.c_char_p, ctypes.c_int,
    ctypes.POINTER(ctypes.c_char_p),
]
_DisBytes.restype = ctypes.c_int

def disassemble_bytes(code: bytes, arch="thumb", mode=2):
    buf = ctypes.create_string_buffer(code)
    out = ctypes.c_char_p()
    rc = _DisBytes(ctypes.cast(buf, ctypes.c_void_p), len(code),
                   arch.encode(), mode, ctypes.byref(out))
    if rc != 0:
        raise RuntimeError(f"sidog error {rc}")
    result = json.loads(ctypes.string_at(out).decode())
    ctypes.CDLL(None).free(out)       # free C string
    return result

