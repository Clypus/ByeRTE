"""WinDivert 2.2 için ctypes bağlaması (yalnızca stdlib).

winws2 ile AYNI WinDivert.dll / WinDivert64.sys kullanılır (data/winws2/...); DLL
sürücüyü kendi dizininde arar. Sürücüyü yüklemek (WinDivertOpen) yönetici ister;
yardımcı fonksiyonlar (checksum, filtre derleme/değerlendirme) istemez.

Handle bir sürece bağlıdır: süreç nasıl biterse bitsin (çökme, TerminateProcess)
çekirdek handle'ı kapatır ve yakalama durur → paketler normal yoluna döner.

Referans: nfq2/windows/windivert/windivert.h (zapret2 v1.0.5.2 ile gelen 2.2 başlığı).
"""

from __future__ import annotations

import ctypes
import logging
import threading
from ctypes import POINTER, byref, c_char_p, c_int, c_int16, c_uint, c_uint8, c_uint32, c_uint64, c_void_p
from pathlib import Path

log = logging.getLogger("byerte.windivert")

# --- Sabitler (windivert.h) --------------------------------------------------

LAYER_NETWORK = 0
LAYER_NETWORK_FORWARD = 1

FLAG_SNIFF = 0x0001
FLAG_DROP = 0x0002
FLAG_RECV_ONLY = 0x0004
FLAG_SEND_ONLY = 0x0008
FLAG_NO_INSTALL = 0x0010
FLAG_FRAGMENTS = 0x0020

PARAM_QUEUE_LENGTH = 0
PARAM_QUEUE_TIME = 1
PARAM_QUEUE_SIZE = 2
PARAM_VERSION_MAJOR = 3
PARAM_VERSION_MINOR = 4

SHUTDOWN_RECV = 0x1
SHUTDOWN_SEND = 0x2
SHUTDOWN_BOTH = 0x3

PRIORITY_HIGHEST = 30000
PRIORITY_LOWEST = -PRIORITY_HIGHEST

MTU_MAX = 40 + 0xFFFF           # en büyük paket (WINDIVERT_MTU_MAX)

# Win32 hata kodları
ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_DATA = 232
ERROR_INVALID_IMAGE_HASH = 577
ERROR_DRIVER_FAILED_PRIOR_UNLOAD = 654
ERROR_OPERATION_ABORTED = 995
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_HOST_UNREACHABLE = 1232
ERROR_DRIVER_BLOCKED = 1275
EPT_S_NOT_REGISTERED = 1753

# WinDivertOpen'ın belgelenmiş hataları için anlaşılır açıklamalar
_OPEN_HINTS = {
    ERROR_ACCESS_DENIED: "yönetici yetkisi gerekli",
    ERROR_FILE_NOT_FOUND: "WinDivert64.sys bulunamadı (WinDivert.dll ile aynı dizinde olmalı)",
    ERROR_INVALID_PARAMETER: "geçersiz filtre / katman / öncelik",
    ERROR_INVALID_IMAGE_HASH: "sürücü imzası doğrulanamadı",
    ERROR_DRIVER_FAILED_PRIOR_UNLOAD: "WinDivert'in uyumsuz bir sürümü yüklü (önce: sc stop WinDivert)",
    ERROR_SERVICE_DOES_NOT_EXIST: "sürücü servisi kurulamadı",
    ERROR_DRIVER_BLOCKED: "sürücünün yüklenmesi sistem tarafından engellendi",
    EPT_S_NOT_REGISTERED: "Temel Filtreleme Altyapısı (BFE) servisi çalışmıyor",
}


class WinDivertError(OSError):
    """WinDivert çağrısı başarısız. .winerror = Win32 hata kodu."""

    def __init__(self, func: str, code: int, hint: str | None = None):
        detail = hint or _format_error(code)
        super().__init__(None, f"{func}: {detail} (hata {code})", None, code)
        self.func = func


def _format_error(code: int) -> str:
    try:
        return ctypes.FormatError(code).strip()
    except Exception:  # noqa: BLE001
        return "bilinmeyen hata"


# --- WINDIVERT_ADDRESS -------------------------------------------------------

class Address(ctypes.Structure):
    """WINDIVERT_ADDRESS (80 bayt). Bit alanları MSVC düzeninde (LSB önce):
    ofset 8'deki 32-bit kelimede Layer 0-7, Event 8-15, Sniffed 16, Outbound 17,
    Loopback 18, Impostor 19, IPv6 20, IPChecksum 21, TCPChecksum 22, UDPChecksum 23.
    Birlik (union) yerine NETWORK katmanı verisi (IfIdx/SubIfIdx) + dolgu."""

    _fields_ = [
        ("Timestamp", ctypes.c_int64),
        ("Layer", c_uint32, 8),
        ("Event", c_uint32, 8),
        ("Sniffed", c_uint32, 1),
        ("Outbound", c_uint32, 1),
        ("Loopback", c_uint32, 1),
        ("Impostor", c_uint32, 1),
        ("IPv6", c_uint32, 1),
        ("IPChecksum", c_uint32, 1),
        ("TCPChecksum", c_uint32, 1),
        ("UDPChecksum", c_uint32, 1),
        ("Reserved1", c_uint32, 8),
        ("Reserved2", c_uint32),
        ("IfIdx", c_uint32),            # union: WINDIVERT_DATA_NETWORK
        ("SubIfIdx", c_uint32),
        ("Reserved3", c_uint8 * 56),    # union'ın kalanı (toplam 64 bayt)
    ]

    def copy(self) -> "Address":
        return Address.from_buffer_copy(self)

    def __repr__(self) -> str:  # teşhis için
        return (f"Address(outbound={self.Outbound}, loopback={self.Loopback}, "
                f"impostor={self.Impostor}, ipv6={self.IPv6}, if={self.IfIdx}.{self.SubIfIdx})")


# --- DLL yükleme -------------------------------------------------------------

_dll_lock = threading.Lock()
_dlls: dict[str, ctypes.CDLL] = {}


def _default_dll_path() -> Path:
    from .. import paths
    return paths.windivert_dll()


def load_dll(path: Path | None = None) -> ctypes.CDLL:
    """WinDivert.dll'i yükle ve prototipleri tanımla (yol başına bir kez).
    DLL'i yüklemek yönetici istemez; sürücü ancak WinDivertOpen ile yüklenir."""
    p = Path(path) if path is not None else _default_dll_path()
    key = str(p.resolve()).lower()
    with _dll_lock:
        dll = _dlls.get(key)
        if dll is not None:
            return dll
        if not p.is_file():
            raise FileNotFoundError(f"WinDivert.dll bulunamadı: {p}")
        dll = ctypes.CDLL(str(p), use_last_error=True)
        _declare(dll)
        _dlls[key] = dll
        return dll


def _declare(dll: ctypes.CDLL) -> None:
    pa = POINTER(Address)
    dll.WinDivertOpen.argtypes = [c_char_p, c_int, c_int16, c_uint64]
    dll.WinDivertOpen.restype = c_void_p
    dll.WinDivertRecv.argtypes = [c_void_p, c_void_p, c_uint, POINTER(c_uint), pa]
    dll.WinDivertRecv.restype = c_int
    dll.WinDivertSend.argtypes = [c_void_p, c_void_p, c_uint, POINTER(c_uint), pa]
    dll.WinDivertSend.restype = c_int
    dll.WinDivertShutdown.argtypes = [c_void_p, c_int]
    dll.WinDivertShutdown.restype = c_int
    dll.WinDivertClose.argtypes = [c_void_p]
    dll.WinDivertClose.restype = c_int
    dll.WinDivertSetParam.argtypes = [c_void_p, c_int, c_uint64]
    dll.WinDivertSetParam.restype = c_int
    dll.WinDivertGetParam.argtypes = [c_void_p, c_int, POINTER(c_uint64)]
    dll.WinDivertGetParam.restype = c_int
    dll.WinDivertHelperCalcChecksums.argtypes = [c_void_p, c_uint, pa, c_uint64]
    dll.WinDivertHelperCalcChecksums.restype = c_int
    dll.WinDivertHelperCompileFilter.argtypes = [c_char_p, c_int, c_void_p, c_uint,
                                                 POINTER(c_char_p), POINTER(c_uint)]
    dll.WinDivertHelperCompileFilter.restype = c_int
    dll.WinDivertHelperEvalFilter.argtypes = [c_char_p, c_void_p, c_uint, pa]
    dll.WinDivertHelperEvalFilter.restype = c_int


_INVALID_HANDLE = c_void_p(-1).value


# --- Yardımcılar (yönetici gerekmez) -----------------------------------------

def calc_checksums(packet: bytes, addr: Address | None = None, flags: int = 0,
                   dll_path: Path | None = None) -> bytes:
    """IPv4/IPv6/UDP/TCP/ICMP sağlama toplamlarını hesapla, yeni paketi döndür.
    addr verilirse IPChecksum/UDPChecksum/... bayrakları da ayarlanır."""
    dll = load_dll(dll_path)
    n = len(packet)
    buf = ctypes.create_string_buffer(bytes(packet), n)
    ok = dll.WinDivertHelperCalcChecksums(buf, n, byref(addr) if addr is not None else None, flags)
    if not ok:
        raise WinDivertError("WinDivertHelperCalcChecksums", ctypes.get_last_error())
    return buf.raw[:n]


def compile_filter(filter: str, layer: int = LAYER_NETWORK,
                   dll_path: Path | None = None) -> tuple[bool, str | None]:
    """Filtre dizesini derle (doğrulama). (geçerli?, hata açıklaması)."""
    dll = load_dll(dll_path)
    err = c_char_p()
    pos = c_uint(0)
    ok = dll.WinDivertHelperCompileFilter(filter.encode("ascii"), layer, None, 0,
                                          byref(err), byref(pos))
    if ok:
        return True, None
    msg = err.value.decode("ascii", "replace") if err.value else "geçersiz filtre"
    return False, f"{msg} (konum {pos.value})"


def eval_filter(filter: str, packet: bytes, addr: Address,
                dll_path: Path | None = None) -> bool:
    """Filtre bu pakete/adrese uyar mı? (sürücüsüz; test ve teşhis için)."""
    dll = load_dll(dll_path)
    buf = ctypes.create_string_buffer(bytes(packet), len(packet))
    return bool(dll.WinDivertHelperEvalFilter(filter.encode("ascii"), buf, len(packet), byref(addr)))


# --- Handle ------------------------------------------------------------------

class WinDivert:
    """Tek bir WinDivert handle'ı.

    recv() tek bir okuyucu iş parçacığından çağrılmalı; send() birden çok iş
    parçacığından çağrılabilir (WinDivert.dll eşzamanlı çağrıları iş parçacığı
    başına olayla yürütür). send/close aynı kilidi kullanır: kapatılmış (ve
    numarası yeniden kullanılmış olabilecek) bir handle'a asla yazılmaz.
    """

    def __init__(self, filter: str, layer: int = LAYER_NETWORK, priority: int = 0,
                 flags: int = 0, dll_path: Path | None = None):
        self.filter = filter
        self.layer = layer
        self.priority = priority
        self.flags = flags
        self._dll_path = dll_path
        self._dll: ctypes.CDLL | None = None
        self._handle: int | None = None
        self._lock = threading.Lock()
        self._recv_buf = None
        self._shut = False

    # bağlam yöneticisi
    def __enter__(self) -> "WinDivert":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def is_open(self) -> bool:
        return self._handle is not None

    def open(self) -> "WinDivert":
        """Handle'ı aç (sürücü gerekirse burada yüklenir — YÖNETİCİ gerekir)."""
        if self._handle is not None:
            return self
        if not (PRIORITY_LOWEST <= self.priority <= PRIORITY_HIGHEST):
            raise ValueError(f"geçersiz öncelik: {self.priority}")
        self._dll = load_dll(self._dll_path)
        h = self._dll.WinDivertOpen(self.filter.encode("ascii"), self.layer,
                                    self.priority, self.flags)
        if h is None or h == _INVALID_HANDLE:
            code = ctypes.get_last_error()
            raise WinDivertError("WinDivertOpen", code, _OPEN_HINTS.get(code))
        self._handle = h
        self._shut = False
        self._recv_buf = ctypes.create_string_buffer(MTU_MAX)
        log.debug("WinDivert açıldı: %s", self.filter)
        return self

    def recv(self) -> tuple[bytes, Address] | None:
        """Bir paket al (bloke eder). shutdown/close sonrası kuyruk boşalınca None."""
        h = self._handle
        if h is None:
            return None
        addr = Address()
        n = c_uint(0)
        buf = self._recv_buf
        ok = self._dll.WinDivertRecv(h, buf, MTU_MAX, byref(n), byref(addr))
        if not ok:
            code = ctypes.get_last_error()
            if self._shut or self._handle is None or code in (ERROR_NO_DATA, ERROR_OPERATION_ABORTED):
                return None
            raise WinDivertError("WinDivertRecv", code)
        return buf.raw[:n.value], addr

    def send(self, packet: bytes, addr: Address) -> int:
        """Paketi enjekte et. addr.Outbound yönü belirler (0 = gelen yön; o zaman
        IfIdx/SubIfIdx geçerli bir arayüz olmalı)."""
        data = bytes(packet)
        with self._lock:
            if self._handle is None:
                raise WinDivertError("WinDivertSend", ERROR_INVALID_HANDLE, "handle kapalı")
            buf = ctypes.create_string_buffer(data, len(data))
            n = c_uint(0)
            ok = self._dll.WinDivertSend(self._handle, buf, len(data), byref(n), byref(addr))
            if not ok:
                raise WinDivertError("WinDivertSend", ctypes.get_last_error())
            return n.value

    def shutdown(self, how: int = SHUTDOWN_BOTH) -> None:
        """Yeni paket kuyruklamayı (ve/veya göndermeyi) durdur. Kuyruk boşalınca
        bekleyen recv() None döner."""
        with self._lock:
            if self._handle is None:
                return
            if how & SHUTDOWN_RECV:
                self._shut = True
            if not self._dll.WinDivertShutdown(self._handle, how):
                log.debug("WinDivertShutdown başarısız: %s", ctypes.get_last_error())

    def close(self) -> None:
        """Handle'ı kapat (idempotent). Bundan sonra paketler yakalanmaz."""
        with self._lock:
            h, self._handle = self._handle, None
            self._shut = True
            if h is not None:
                if not self._dll.WinDivertClose(h):
                    log.debug("WinDivertClose başarısız: %s", ctypes.get_last_error())
                log.debug("WinDivert kapandı: %s", self.filter)

    def set_param(self, param: int, value: int) -> None:
        with self._lock:
            if self._handle is None:
                raise WinDivertError("WinDivertSetParam", ERROR_INVALID_HANDLE, "handle kapalı")
            if not self._dll.WinDivertSetParam(self._handle, param, value):
                raise WinDivertError("WinDivertSetParam", ctypes.get_last_error())

    def get_param(self, param: int) -> int:
        with self._lock:
            if self._handle is None:
                raise WinDivertError("WinDivertGetParam", ERROR_INVALID_HANDLE, "handle kapalı")
            v = c_uint64(0)
            if not self._dll.WinDivertGetParam(self._handle, param, byref(v)):
                raise WinDivertError("WinDivertGetParam", ctypes.get_last_error())
            return v.value
