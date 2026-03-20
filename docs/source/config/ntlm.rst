.. _config_ntlm:

NTLM
====

Section ``[NTLM]``
------------------

.. py:currentmodule:: NTLM

Dementor's NTLM module (``ntlm.py``) implements the server side of the
three-message NTLM handshake per `[MS-NLMP] <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>`__.
It is a **capture module** — it builds a valid ``CHALLENGE_MESSAGE`` to keep
the handshake alive, extracts crackable hashes from the
``AUTHENTICATE_MESSAGE``, formats them for hashcat, and writes them to the
database.  It does not verify responses, compute session keys, or participate
in post-authentication signing, sealing, or encryption.

The ``[NTLM]`` config section provides **global defaults** shared by every
protocol that uses NTLM (SMB, HTTP, LDAP, MSSQL, etc.).  Each protocol can
override any ``[NTLM]`` option in its own section using the ``NTLM.`` prefix
(e.g. ``NTLM.Challenge`` inside ``[SMB]``).  The resolution order is:

    ``[[Protocol.Server]]`` |rarr| ``[Protocol]`` |rarr| ``[NTLM]`` |rarr|
    code default

.. |rarr| unicode:: U+2192


Options
-------

Capture Behaviour
~~~~~~~~~~~~~~~~~

.. py:attribute:: Challenge
    :type: HexStr | str
    :value: None (random at startup)

    *Linked to* :attr:`config.SessionConfig.ntlm_challenge`

    The 8-byte ``ServerChallenge`` nonce sent in the ``CHALLENGE_MESSAGE``.
    Accepts any of the following formats:

    - ``"hex:1122334455667788"`` — explicit hex (recommended)
    - ``"ascii:1337LEET"`` — explicit ASCII (recommended)
    - ``"1122334455667788"`` — 16 hex characters (auto-detected as hex)
    - ``"1337LEET"`` — 8 ASCII characters (auto-detected as ASCII)

    If omitted, a cryptographically random challenge is generated once at
    startup and reused for all connections during that run.

    .. tip::

        **For NTLMv1 cracking:** a fixed challenge such as
        ``"1122334455667788"`` combined with rainbow tables (e.g.
        `crack.sh <https://crack.sh>`__) can crack NTLMv1 hashes offline
        without GPU resources.

        **For NTLMv2 cracking:** the challenge value does not matter —
        NTLMv2 incorporates the challenge into an HMAC-MD5 construction
        that is not amenable to rainbow tables.  Use hashcat ``-m 5600``
        with a wordlist or rules.

    .. container:: demo

        .. code-block:: text
            :emphasize-lines: 21

            NetBIOS Session Service
            SMB2 (Server Message Block Protocol version 2)
                SMB2 Header
                    [...]
                Session Setup Response (0x01)
                    StructureSize: 0x0009
                    Session Flags: 0x0000
                    Blob Offset: 0x00000048
                    Blob Length: 201
                    Security Blob [...]:
                        GSS-API Generic Security Service Application Program Interface
                            Simple Protected Negotiation
                                negTokenTarg
                                    negResult: accept-incomplete (1)
                                    supportedMech: 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
                                    NTLM Secure Service Provider
                                        NTLMSSP identifier: NTLMSSP
                                        NTLM Message Type: NTLMSSP_CHALLENGE (0x00000002)
                                        Target Name: WORKGROUP
                                        [...] Negotiate Flags: 0xe28a0217
                                        NTLM Server Challenge: 74d6b7f11d68baa2
                                        Reserved: 0000000000000000
                                        Target Info
                                        Version 255.255 (Build 65535); NTLM Current Revision 255


.. py:attribute:: DisableExtendedSessionSecurity
    :value: false
    :type: bool

    *Linked to* :attr:`config.SessionConfig.ntlm_disable_ess`

    When ``true``, strips ``NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY``
    (flag P, bit 19) from the ``CHALLENGE_MESSAGE``, preventing ESS
    negotiation.

    **Effect on captured hashes:**

    - ``false`` (default) — ESS is negotiated when the client requests it.
      NTLMv1 clients (LmCompatibilityLevel 0-2) produce **NetNTLMv1-ESS**
      hashes (hashcat ``-m 5500``).  ESS uses
      ``MD5(ServerChallenge || ClientChallenge)[0:8]`` as the effective
      challenge; hashcat derives this internally from the emitted
      ``ClientChallenge`` field.

    - ``true`` — ESS is suppressed.  NTLMv1 clients produce plain
      **NetNTLMv1** hashes.  A fixed :attr:`Challenge` combined with
      rainbow tables can crack these without GPU resources.

    NTLMv2 clients (level 3+, all modern Windows) are **unaffected** —
    they always produce NetNTLMv2 regardless of ESS.

    .. note::

        Dementor classifies ESS from the ``LmChallengeResponse`` byte
        structure (``LM[8:24] == Z(16)``) rather than solely from the
        negotiate flag, so classification is accurate even when this setting
        is toggled or when the client and server disagree on ESS.

    .. py:attribute:: ExtendedSessionSecurity
        :value: true
        :type: bool

        .. deprecated:: 1.0.0.dev19
            Renamed to :attr:`DisableExtendedSessionSecurity`.


.. py:attribute:: DisableNTLMv2
    :value: false
    :type: bool

    *Linked to* :attr:`config.SessionConfig.ntlm_disable_ntlmv2`

    When ``true``, clears ``NTLMSSP_NEGOTIATE_TARGET_INFO`` and omits the
    ``TargetInfoFields`` (AV_PAIRs) from the ``CHALLENGE_MESSAGE``.

    **Effect on captured hashes:**

    - ``false`` (default) — ``TargetInfoFields`` is populated.  Clients can
      construct an NTLMv2 response and produce **NetNTLMv2** (and sometimes
      **NetLMv2**) hashes (hashcat ``-m 5600``).

    - ``true`` — ``TargetInfoFields`` is empty.  Without it, clients cannot
      build the NTLMv2 ``NTLMv2_CLIENT_CHALLENGE`` blob per [MS-NLMP]
      §3.3.2.  LmCompatibilityLevel 0-2 clients fall back to NTLMv1.
      **Level 3+ clients** (all modern Windows defaults) **fail
      authentication entirely** and produce **zero captured hashes**.

    .. warning::

        This setting is almost never useful.  Clients at level 0-2 already
        send NTLMv1 unconditionally and will never send NTLMv2 regardless
        of whether ``TargetInfoFields`` is present.  This option therefore
        only affects level 3+ clients, which **require** ``TargetInfoFields``
        to construct the NTLMv2 blob.  Without it, those clients abort the
        handshake and produce zero captures.  Use only when exclusively
        targeting known legacy NTLMv1-only environments.


Server Identity
~~~~~~~~~~~~~~~

These options control the identity values embedded in the NTLM
``CHALLENGE_MESSAGE``.  They determine what appears on the wire, in
captured hash lines, and in NTLMv2 ``AV_PAIR`` structures.  **No client
changes authentication behavior** based on any of these values — they are
cosmetic from the client's perspective but operationally important for
blending in and for hash formatting.

When set in the ``[NTLM]`` section, these serve as global defaults.
Per-protocol overrides use the ``NTLM.`` prefix (e.g. ``NTLM.TargetType``
inside ``[SMB]``).

.. py:attribute:: TargetType
    :type: str
    :value: "server"

    Sets the ``NTLMSSP_TARGET_TYPE`` flag in the ``CHALLENGE_MESSAGE``
    and determines the ``TargetName`` field value:

    - ``"server"`` — sets ``NTLMSSP_TARGET_TYPE_SERVER`` (bit 17);
      ``TargetName`` is the NetBIOS computer name.
    - ``"domain"`` — sets ``NTLMSSP_TARGET_TYPE_DOMAIN`` (bit 16);
      ``TargetName`` is the NetBIOS domain name.

.. py:attribute:: Version
    :type: str
    :value: "0.0.0" (all-zero placeholder)

    The ``VERSION`` structure in the ``CHALLENGE_MESSAGE``, formatted as
    ``"major.minor.build"`` (e.g. ``"10.0.20348"`` for Server 2022).
    Clients do not verify this value per [MS-NLMP] §2.2.2.10.

    Common values:

    .. list-table::
        :widths: 20 30
        :header-rows: 1

        * - Version
          - OS
        * - ``"5.1.2600"``
          - Windows XP SP3
        * - ``"6.1.7601"``
          - Windows 7 SP1 / Server 2008 R2
        * - ``"6.3.9600"``
          - Windows 8.1 / Server 2012 R2
        * - ``"10.0.19041"``
          - Windows 10 (20H1)
        * - ``"10.0.20348"``
          - Windows Server 2022

.. py:attribute:: NetBIOSComputer
    :type: str
    :value: None

    AV_PAIR ``MsvAvNbComputerName`` (``0x0001``) in the ``CHALLENGE_MESSAGE``
    ``TargetInfoFields``.  When ``None``, falls back to the calling
    protocol's own computer name (e.g. :attr:`SMB.NetBIOSComputer`).

.. py:attribute:: NetBIOSDomain
    :type: str
    :value: None

    AV_PAIR ``MsvAvNbDomainName`` (``0x0002``).  When ``None``, falls back
    to the calling protocol's own domain name (e.g. :attr:`SMB.NetBIOSDomain`).

.. py:attribute:: DnsComputer
    :type: str
    :value: None

    AV_PAIR ``MsvAvDnsComputerName`` (``0x0003``).  When ``None``, derived
    as ``"{NetBIOSComputer}.{DnsDomain}"`` if the server appears
    domain-joined, or just ``"{NetBIOSComputer}"`` if standalone.

.. py:attribute:: DnsDomain
    :type: str
    :value: None

    AV_PAIR ``MsvAvDnsDomainName`` (``0x0004``).  When ``None``, falls back
    to the calling protocol's domain name.

.. py:attribute:: DnsTree
    :type: str
    :value: None

    AV_PAIR ``MsvAvDnsTreeName`` (``0x0005``).  Omitted entirely when the
    server appears to be workgroup-joined (domain is empty or
    ``"WORKGROUP"``).  When ``None`` and domain-joined, defaults to the
    value of :attr:`DnsDomain`.


Protocol Behaviour
------------------

Three-Message Handshake
~~~~~~~~~~~~~~~~~~~~~~~

Dementor acts as a **capture server**, not an authentication server.  Per
[MS-NLMP] §1.3.1.1, the handshake proceeds as follows:

.. code-block:: text

    Client                              Server (Dementor)
      |                                       |
      |--- NEGOTIATE_MESSAGE ---------------► |  inspect client flags,
      |                                       |  extract OS/domain/workstation
      |◄-- CHALLENGE_MESSAGE ---------------- |  Dementor controls entirely:
      |                                       |  challenge, flags, AV_PAIRs
      |--- AUTHENTICATE_MESSAGE ------------► |  extract & classify hashes,
      |                                       |  format for hashcat, write to DB
      |                                       |

The connection is terminated (or returned to the calling protocol handler)
immediately after the ``AUTHENTICATE_MESSAGE`` is processed.


CHALLENGE_MESSAGE Construction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``CHALLENGE_MESSAGE`` is built by ``NTLM_build_challenge_message()``
per [MS-NLMP] §3.2.5.1.1.  It is the **only message Dementor authors** —
the other two are client-originated.

**Flag mirroring:**

The following client-requested flags are echoed back when present:

.. list-table::
    :widths: 30 50 20
    :header-rows: 1

    * - Flag
      - Purpose
      - Letter
    * - ``NEGOTIATE_SIGN``
      - Message signing support
      - D
    * - ``NEGOTIATE_SEAL``
      - Message encryption support
      - E
    * - ``NEGOTIATE_ALWAYS_SIGN``
      - Set session security in connection
      - M
    * - ``NEGOTIATE_KEY_EXCH``
      - Session key negotiation
      - V
    * - ``NEGOTIATE_56``
      - 56-bit encryption
      - W
    * - ``NEGOTIATE_128``
      - 128-bit encryption
      - U
    * - ``NEGOTIATE_UNICODE``
      - UTF-16LE string encoding
      - A
    * - ``NEGOTIATE_OEM``
      - OEM (cp437) string encoding
      - B

.. important::

    Failing to echo ``NEGOTIATE_SIGN`` causes strict clients (e.g. Windows
    10 with ``RequireSecuritySignature = 1``) to abort before sending the
    ``AUTHENTICATE_MESSAGE``, losing the capture entirely.

**ESS / LM_KEY mutual exclusivity:**

When the client requests both ``NEGOTIATE_EXTENDED_SESSIONSECURITY`` (P) and
``NEGOTIATE_LM_KEY`` (G), only ESS is returned.  Per [MS-NLMP] §2.2.2.5,
these flags are mutually exclusive — ESS takes priority.

**Server-set flags:**

- ``NTLMSSP_NEGOTIATE_NTLM`` — always set (NTLM authentication)
- ``NTLMSSP_REQUEST_TARGET`` — always set (TargetName present)
- ``NTLMSSP_TARGET_TYPE_SERVER`` or ``_DOMAIN`` — per :attr:`TargetType`
- ``NTLMSSP_NEGOTIATE_TARGET_INFO`` — set unless :attr:`DisableNTLMv2`
- ``NTLMSSP_NEGOTIATE_VERSION`` — echoed when the client requests it


AV_PAIRs (``TargetInfoFields``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When :attr:`DisableNTLMv2` is ``false`` (the default), ``TargetInfoFields``
is populated with AV_PAIRs per [MS-NLMP] §2.2.2.1.  These values come from
explicit config options, with a per-protocol fallback chain:

.. list-table::
    :header-rows: 1
    :widths: 10 20 70

    * - AvId
      - Constant
      - Resolution (SMB example)
    * - ``0x0001``
      - ``MsvAvNbComputerName``
      - :attr:`NTLM.NetBIOSComputer` |rarr| :attr:`SMB.NetBIOSComputer`
    * - ``0x0002``
      - ``MsvAvNbDomainName``
      - :attr:`NTLM.NetBIOSDomain` |rarr| :attr:`SMB.NetBIOSDomain`
    * - ``0x0003``
      - ``MsvAvDnsComputerName``
      - :attr:`NTLM.DnsComputer` |rarr| derived as
        ``"{nb_computer}.{dns_domain}"`` if domain-joined, else
        ``"{nb_computer}"``
    * - ``0x0004``
      - ``MsvAvDnsDomainName``
      - :attr:`NTLM.DnsDomain` |rarr| :attr:`SMB.NetBIOSDomain`
    * - ``0x0005``
      - ``MsvAvDnsTreeName``
      - :attr:`NTLM.DnsTree` |rarr| value of ``DnsDomain`` if
        domain-joined; **omitted entirely** if standalone
    * - ``0x0007``
      - ``MsvAvTimestamp``
      - **Intentionally omitted** — see below
    * - ``0x0000``
      - ``MsvAvEOL``
      - Always appended (list terminator)

All AV_PAIR values are encoded as **UTF-16LE** per [MS-NLMP] §2.2.1.2,
regardless of the negotiated character set.

**MsvAvTimestamp omission:**

``MsvAvTimestamp`` (``0x0007``) is intentionally omitted from the
``CHALLENGE_MESSAGE``.  Per [MS-NLMP] §3.3.2 rule 7, when the server
includes ``MsvAvTimestamp``, the client **MUST** suppress its
``LmChallengeResponse`` (set it to ``Z(24)``), which eliminates the
NetLMv2 companion hash.

Omitting it allows clients at LmCompatibilityLevel 0-2 (Vista, Server 2008)
to send both NetNTLMv2 and LMv2 responses.  See
`LMv2 Companion Capture`_ for the full picture.


Hash Types and Classification
-----------------------------

Four hash types are extracted from the ``AUTHENTICATE_MESSAGE``, classified
by NT and LM response **byte structure** per [MS-NLMP] §3.3.  The ESS flag
is cross-checked but the byte structure is **authoritative**:

.. list-table::
    :header-rows: 1
    :widths: 18 12 35 12

    * - Type
      - NT length
      - LM condition
      - HC mode
    * - ``NetNTLMv1``
      - 24 bytes
      - any (real LM response or absent)
      - ``-m 5500``
    * - ``NetNTLMv1-ESS``
      - 24 bytes
      - 24 bytes with ``LM[8:24] == Z(16)`` (ESS signature)
      - ``-m 5500``
    * - ``NetNTLMv2``
      - > 24 bytes
      - n/a (NTProofStr + blob)
      - ``-m 5600``
    * - ``NetLMv2``
      - > 24 bytes
      - 24 bytes, non-null, non-Z(24) (LMv2 companion)
      - ``-m 5600``

NetLMv2 is always paired with NetNTLMv2 on the same connection; both use
hashcat ``-m 5600``.


Hashcat Output Formats
~~~~~~~~~~~~~~~~~~~~~~

Each captured hash is written in hashcat-compatible format.  Validated
against hashcat ``module_05500.c`` and ``module_05600.c``:

.. code-block:: text

    # NetNTLMv1 / NetNTLMv1-ESS  (hashcat -m 5500)
    User::Domain:LmResponse(48 hex):NtResponse(48 hex):ServerChallenge(16 hex)

    # NetNTLMv2  (hashcat -m 5600)
    User::Domain:ServerChallenge(16 hex):NTProofStr(32 hex):Blob(var hex)

    # NetLMv2  (hashcat -m 5600)
    User::Domain:ServerChallenge(16 hex):LMProof(32 hex):ClientChallenge(16 hex)

For **NetNTLMv1-ESS**, the raw ``ServerChallenge`` is emitted (not the
derived ``MD5(Server || Client)[0:8]``).  Hashcat ``-m 5500`` auto-detects
ESS from ``LM[8:24] == Z(16)`` and derives the mixed challenge internally.


LM Response Filtering
~~~~~~~~~~~~~~~~~~~~~~

For **NetNTLMv1** captures, the LM slot in the hashcat line is omitted when
any of the following conditions hold:

- **Identical response** — ``LmChallengeResponse == NtChallengeResponse``.
  This occurs at LmCompatibilityLevel 2, where the client copies the NT
  response into both slots.  Using the LM copy with the NT one-way
  function during cracking would yield incorrect results.
- **Long-password placeholder** — ``LmChallengeResponse == DESL(Z(16))``.
  Clients send this deterministic value when the password exceeds 14
  characters or the ``NoLMHash`` registry policy is enforced.  It carries
  no crackable material.
- **Empty-password placeholder** — ``LmChallengeResponse == DESL(LMOWFv1(""))``.
  The LM derivative of an empty password; equally uncrackable.


.. _lmv2_companion:

LMv2 Companion Capture
~~~~~~~~~~~~~~~~~~~~~~~

For **NetNTLMv2** captures, the NetLMv2 companion hash is captured alongside
the primary NetNTLMv2 response when all of the following hold:

1. ``LmChallengeResponse`` is exactly 24 bytes
2. ``LmChallengeResponse`` is not ``Z(24)`` (all zeros)
3. ``LmChallengeResponse`` is not ``Z(16)`` (truncated zeros)

**When clients suppress LMv2:**

Clients set ``LmChallengeResponse`` to ``Z(24)`` in three situations:

- **MsvAvTimestamp present in CHALLENGE_MESSAGE** — Per [MS-NLMP] §3.3.2
  rule 7, when the server includes ``MsvAvTimestamp`` (``0x0007``) in the
  AV_PAIR list, the client MUST suppress ``LmChallengeResponse``.
  Dementor intentionally omits ``MsvAvTimestamp`` to avoid this.

- **Extended Protection enabled (Win 7+ / Server 2008 R2+)** — Windows 7
  and Server 2008 R2 introduced Extended Protection for Integrated
  Authentication (KB976918), which is **enabled by default**.  When
  Extended Protection is active, the NTLM SSPI layer suppresses
  ``LmChallengeResponse`` and sets it to ``Z(24)`` as part of the
  enhanced authentication binding.  This is the primary reason modern
  clients do not send LMv2 — it is not LmCompatibilityLevel that
  controls this, but the Extended Protection feature.  See
  `Extended Protection and Channel Binding Tokens`_ for details and
  the registry workaround.

- **LmCompatibilityLevel 3+ with NtlmMinClientSec** — In some hardened
  configurations, ``NtlmMinClientSec`` (``HKLM\...\LSA\MSV1_0``) can
  require NTLM 2 session security (``0x00080000``), which also
  suppresses the LMv2 response.

**Observed real-world behavior** (from live testing against 14 Windows VMs,
all at default LmCompatibilityLevel 3, Dementor omitting MsvAvTimestamp):

.. list-table::
    :header-rows: 1
    :widths: 30 15 55

    * - Client
      - LMv2?
      - Reason
    * - Vista SP2
      - **Yes**
      - No Extended Protection (feature did not exist yet)
    * - Server 2008
      - **Yes**
      - No Extended Protection (pre-dates the feature)
    * - Win 7 SP1
      - No
      - Extended Protection ON by default (KB976918)
    * - Win 8.1
      - No
      - Extended Protection ON
    * - Win 10
      - No
      - Extended Protection ON
    * - Win 11
      - No
      - Extended Protection ON
    * - Server 2008 R2
      - No
      - Extended Protection ON by default
    * - Server 2012 R2 through 2022
      - No
      - Extended Protection ON

The dividing line is exact: **Vista / Server 2008** send LMv2 (no
Extended Protection), **Win 7 / Server 2008 R2 and later** suppress it
(Extended Protection enabled by default).

To re-enable LMv2 from Win 7+ clients, set the client-side registry value
``SuppressExtendedProtection = 0x01`` at
``HKLM\System\CurrentControlSet\Control\LSA``.  See
`Extended Protection and Channel Binding Tokens`_ for the full registry
reference.


Anonymous Authentication
~~~~~~~~~~~~~~~~~~~~~~~~

``AUTHENTICATE_MESSAGE`` tokens are checked for anonymous (null-session)
authentication before any hash is extracted.  A token is treated as
anonymous when:

- ``NTLMSSP_NEGOTIATE_ANONYMOUS`` (flag ``0x00000800``) is set, **or**
- ``UserName`` is empty, ``NtChallengeResponse`` is empty, and
  ``LmChallengeResponse`` is empty or ``Z(1)`` (per §3.2.5.1.2)

On any parse error the check conservatively returns ``True`` (anonymous) to
avoid writing a malformed capture.  Anonymous tokens are silently discarded.

.. note::

    XP SP3 and XP SP0 send an anonymous ``AUTHENTICATE_MESSAGE`` probe
    before the real credential auth on each connection.  This is normal
    SSPI behavior — the anonymous probe is discarded and the real auth
    that follows is captured.


Client Information Leakage
--------------------------

Each NTLM message leaks client metadata that Dementor extracts and logs.
The three messages provide increasingly detailed information:

.. list-table::
    :header-rows: 1
    :widths: 30 15 15 15

    * - Field
      - NEGOTIATE
      - CHALLENGE
      - AUTHENTICATE
    * - OS version (``VERSION`` structure)
      - Yes [1]_
      - *(server-set)*
      - Yes
    * - Workstation name
      - Yes [2]_
      - *(server-set)*
      - Yes
    * - Domain name
      - Yes [2]_
      - *(server-set)*
      - Yes
    * - Username
      - No
      - —
      - Yes
    * - NegotiateFlags
      - Yes
      - *(server-set)*
      - Yes
    * - NTLMv2 blob AV_PAIRs
      - No
      - —
      - Yes (NTLMv2 only)
    * - SPN (``MsvAvTargetName``, 0x0009)
      - No
      - —
      - Yes (NTLMv2 only) [3]_
    * - Client timestamp (``MsvAvTimestamp``, 0x0007)
      - No
      - —
      - Yes (NTLMv2 only)
    * - MIC (Message Integrity Code)
      - No
      - —
      - Yes (if VERSION flag set)
    * - Channel Bindings (``MsvAvChannelBindings``, 0x000A)
      - No
      - —
      - Yes (NTLMv2 only) [4]_
    * - ``MsvAvFlags`` (0x0006)
      - No
      - —
      - Yes (NTLMv2 only)

.. [1] Only when ``NTLMSSP_NEGOTIATE_VERSION`` is set.  XP SP0 does not
   set this flag and sends no VERSION structure.

.. [2] NEGOTIATE_MESSAGE domain and workstation are OEM-encoded and often
   empty on modern clients.  The AUTHENTICATE_MESSAGE values are
   authoritative.

.. [3] The SPN reveals what service the client was trying to reach, e.g.
   ``cifs/10.0.0.50`` or ``HTTP/intranet.corp.com``.  Valuable for
   understanding lateral movement paths.

.. [4] Channel Binding Tokens (CBT) are part of Extended Protection for
   Authentication (KB976918).  Win 7+ includes CBT when Extended Protection
   is active; this also suppresses LMv2.  See
   `Extended Protection and Channel Binding Tokens`_.


Logging
-------

Dementor emits structured log messages at each stage of the NTLM handshake.
All NTLM log messages are prefixed by the calling protocol's logger (e.g.
``SMB``).

**Debug level** (``--debug``):

.. code-block:: text

    C: NTLMSSP NEGOTIATE: flags=0xe2898217 os='Windows 10 Build 19041' domain='CORP' workstation='LAPTOP'
    NTLMSSP CHALLENGE: flags=0xe2898217 challenge=544553544348414c target=NTLMREALM
    C: NTLMSSP AUTHENTICATE: flags=0xe2898217 os='Windows 10 Build 19041' user='jsmith' domain='CORP' name='LAPTOP' NT_len=318 LM_len=24 MIC=aabb...
    NTLMv2 blob: ClientChallenge=aabbccddeeff0011 SPN=cifs/10.0.0.50 Timestamp=0x01d5... Flags=0x00000000 ChannelBindings=(empty)
    Extracting hashes: user='jsmith' domain='CORP' hash_type=NetNTLMv2 nt_len=318 lm_len=24
    Appended NetNTLMv2 hash (nt_len=318)
    Writing 1 hash(es) to capture database for user='jsmith' domain='CORP'

**Display level** (default):

.. code-block:: text

    NTLM: os:Windows 10 Build 19041 | user:jsmith | domain:CORP | name:LAPTOP | SPN:cifs/10.0.0.50

The display line merges fields from both the NEGOTIATE (Type 1) and
AUTHENTICATE (Type 3) messages, with Type 3 values taking priority on
conflicts.  The field set is: ``os``, ``user``, ``domain``, ``name``
(workstation), ``SPN`` (from NTLMv2 blob).

**Success level** (cleartext only):

.. code-block:: text

    Cleartext password captured: jsmith\CORP

Emitted only for SMB1 basic-security cleartext captures (Path B).


LmCompatibilityLevel Reference
-------------------------------

The Windows ``LmCompatibilityLevel`` registry value
(``HKLM\SYSTEM\CurrentControlSet\Control\Lsa``) controls which NTLM
response types a client sends.  This is the **single most important client
setting** for hash capture — it determines what Dementor can extract.

.. list-table::
    :header-rows: 1
    :widths: 6 30 22 10 32

    * - Level
      - Client sends
      - Captured type
      - HC mode
      - Notes
    * - 0
      - LMv1 + NTLMv1
      - NetNTLMv1 or NetNTLMv1-ESS
      - ``5500``
      - Real LM response included
    * - 1
      - LMv1 + NTLMv1 (ESS if negotiated)
      - NetNTLMv1 / NetNTLMv1-ESS
      - ``5500``
      - ESS when server offers it
    * - 2
      - NTLMv1 in both LM and NT slots
      - NetNTLMv1 (LM slot filtered)
      - ``5500``
      - LM slot is a copy of NT — filtered out
    * - 3
      - NTLMv2 + LMv2
      - NetNTLMv2 (+ LMv2 [5]_)
      - ``5600``
      - **Default since Vista/Server 2008**
    * - 4
      - NTLMv2 + LMv2; refuse LM at DC
      - NetNTLMv2 (+ LMv2 [5]_)
      - ``5600``
      - Server-side LM refusal (DC only)
    * - 5
      - NTLMv2 + LMv2; refuse LM & NTLM at DC
      - NetNTLMv2 (+ LMv2 [5]_)
      - ``5600``
      - Server-side LM+NTLM refusal (DC only)

.. [5] LMv2 is only captured from clients **without** Extended Protection
   (Vista, Server 2008).  Win 7+ and Server 2008 R2+ have Extended
   Protection enabled by default and suppress LMv2 (``LM = Z(24)``)
   regardless of LmCompatibilityLevel.  See `LMv2 Companion Capture`_
   and `Extended Protection and Channel Binding Tokens`_.

.. note::

    **Default values:**

    - **Windows Vista and later:** level 3 (send NTLMv2 only)
    - **Windows XP / Server 2003:** level 0 or 1 (send LM + NTLM)
    - **Standalone servers** (non-domain): level 3

    Levels 0-2 are only found on legacy systems or when explicitly
    downgraded via Group Policy (``secpol.msc`` |rarr| Local Policies
    |rarr| Security Options |rarr| "Network security: LAN Manager
    authentication level").

    Leave :attr:`DisableNTLMv2` at ``false`` (the default) to capture
    hashes from clients at **any** level.

**Interaction with Dementor settings:**

.. list-table::
    :header-rows: 1
    :widths: 20 15 15 15 15 20

    * - Dementor setting
      - Level 0-1
      - Level 2
      - Level 3-5
      - Hash captured
      - Use case
    * - Default (all false)
      - NTLMv1-ESS
      - NTLMv1
      - NTLMv2
      - All types
      - Maximum coverage
    * - DisableESS = true
      - **NTLMv1**
      - NTLMv1
      - NTLMv2
      - NTLMv1 easier to crack
      - Rainbow table attack
    * - DisableNTLMv2 = true
      - NTLMv1-ESS
      - NTLMv1
      - **NONE**
      - Loses all modern clients
      - Legacy-only targeting


Extended Protection and Channel Binding Tokens
-----------------------------------------------

Windows 7 and Server 2008 R2 introduced **Extended Protection for
Integrated Authentication** (KB976918).  This feature is **enabled by
default** and has two components that directly affect NTLM credential
capture:

1. **Channel Binding Tokens (CBT)** — binds NTLM authentication to the
   outer TLS channel, preventing relay attacks across TLS endpoints.
2. **LMv2 response suppression** — as a side effect of Extended
   Protection, the NTLM SSPI layer sets ``LmChallengeResponse`` to
   ``Z(24)`` instead of sending a real LMv2 response.

This is the reason that **Win 7+ and Server 2008 R2+ do not send LMv2**
in the ``AUTHENTICATE_MESSAGE``, even when Dementor omits
``MsvAvTimestamp`` from the ``CHALLENGE_MESSAGE``.  Vista and Server 2008
predate this feature and still send real LMv2.

**How CBT works:**

When authentication occurs inside a TLS channel (e.g. HTTPS, LDAPS), the
client computes a hash of the server's TLS certificate and includes it as
``MsvAvChannelBindings`` (AV_PAIR ``0x000A``) in the NTLMv2
``AUTHENTICATE_MESSAGE`` blob.  The authentication request is also bound
to the Service Principal Name (SPN) used to initiate the connection.  The
server validates that the authentication was intended for *this specific
endpoint*, preventing relay attacks where an attacker forwards credentials
to a different server.

**Impact on Dementor by protocol:**

- **SMB (port 445/139):** Hash capture is unaffected.  SMB does not use
  TLS for the NTLM handshake, so there is no outer channel to bind to
  and CBT does not prevent authentication.  However, the LMv2
  suppression side-effect still applies — Win 7+ clients send
  ``LM = Z(24)`` even over plain SMB.

- **TLS-wrapped protocols (HTTPS, LDAPS):** CBT can prevent
  authentication if the client binds to a different certificate than
  the one Dementor presents.  The ``MsvAvChannelBindings`` value in the
  NTLMv2 blob reveals whether the client attempted channel binding.
  Dementor extracts and logs this at debug level.

**SuppressExtendedProtection registry key (client-side):**

The ``SuppressExtendedProtection`` value at
``HKLM\System\CurrentControlSet\Control\LSA`` controls the Extended
Protection behavior on the client.  This is the key lever for restoring
LMv2 capture from Win 7+ clients:

.. list-table::
    :header-rows: 1
    :widths: 15 45 40

    * - Value
      - Effect
      - LMv2 impact
    * - ``0x00``
      - Default — Extended Protection fully active; CBT emitted, LMv2
        suppressed
      - ``LM = Z(24)`` — **no LMv2 captured**
    * - ``0x01``
      - Extended Protection suppressed for NTLM and Kerberos.  NTLM
        provides LMv2 responses; CBT tokens not emitted
      - **LMv2 restored** — real LMv2 captured
    * - ``0x03``
      - CBT never emitted (Kerberos); NTLM same as ``0x01``
      - **LMv2 restored**

.. important::

    Setting ``SuppressExtendedProtection = 0x01`` on a target client
    **re-enables LMv2** and also removes the relay protection that
    Extended Protection provides.  This is a security downgrade and is
    only relevant for environments where you control the client
    configuration (lab testing, authorized assessments).

**NtlmMinClientSec (session security requirements):**

A separate registry value at ``HKLM\...\LSA\MSV1_0\NtlmMinClientSec``
controls the minimum session security requirements for NTLM connections.
When set to ``0x00080000`` (require NTLM 2 session security), the client
will refuse to authenticate unless NTLMv2 session security is negotiated.
This does not directly suppress LMv2, but it prevents NTLMv1 fallback
when :attr:`DisableNTLMv2` is ``true``.

**Time skew and authentication failures:**

KB976918 also documents that NTLM authentication fails when there is a
significant time difference between the client and the domain controller
(or workgroup server).  The client's ``MsvAvTimestamp`` in the NTLMv2
blob is checked against the server's time.  Since Dementor is a capture
server that does not validate responses, **time skew does not affect hash
capture** — but it may explain why a legitimate DC rejected the same
credentials that Dementor captured successfully.  Setting
``SuppressExtendedProtection = 0x01`` on the client also removes the
time-skew check per KB976918.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: NTLM configuration section (all options)

    [NTLM]
    # 8-byte ServerChallenge nonce.  Accepted formats:
    #   "hex:1122334455667788"  — explicit hex (recommended)
    #   "ascii:1337LEET"        — explicit ASCII (recommended)
    #   "1122334455667788"      — 16 hex chars, auto-detected
    #   "1337LEET"              — 8 ASCII chars, auto-detected
    # Omit entirely for a cryptographically random value per run.
    Challenge = "1337LEET"

    # Strip NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.
    # false (default): ESS negotiated → NetNTLMv1-ESS (hashcat -m 5500).
    # true:            ESS suppressed → plain NetNTLMv1; crackable with
    #                  rainbow tables when combined with a fixed Challenge.
    DisableExtendedSessionSecurity = false

    # Omit TargetInfoFields (AV_PAIRS) from CHALLENGE_MESSAGE.
    # false (default): NetNTLMv2 + NetLMv2 captured from modern clients.
    # true:            Level 0-2 clients fall back to NTLMv1; level 3+
    #                  (all modern Windows) will FAIL — NO captures.
    DisableNTLMv2 = false

    # Server identity in the CHALLENGE_MESSAGE:
    # TargetType = "server"           # or "domain"
    # Version = "10.0.20348"          # Server 2022
    # NetBIOSComputer = "FILESVR01"   # AV_PAIR 0x0001
    # NetBIOSDomain = "CORP"          # AV_PAIR 0x0002
    # DnsComputer = "filesvr01.corp.local"  # AV_PAIR 0x0003
    # DnsDomain = "corp.local"        # AV_PAIR 0x0004
    # DnsTree = "corp.local"          # AV_PAIR 0x0005


Spec References
---------------

.. list-table::
    :widths: 20 80
    :header-rows: 1

    * - Document
      - Covers
    * - **[MS-NLMP]**
      - NT LAN Manager (NTLM) Authentication Protocol
    * - **[MS-NLMP] §1.3.1.1**
      - Three-message handshake overview
    * - **[MS-NLMP] §2.2.1.2**
      - ``CHALLENGE_MESSAGE`` structure
    * - **[MS-NLMP] §2.2.1.3**
      - ``AUTHENTICATE_MESSAGE`` structure
    * - **[MS-NLMP] §2.2.2.1**
      - ``AV_PAIR`` structures (TargetInfoFields)
    * - **[MS-NLMP] §2.2.2.5**
      - ``NegotiateFlags`` (letters A-W)
    * - **[MS-NLMP] §2.2.2.10**
      - ``VERSION`` structure
    * - **[MS-NLMP] §3.2.5.1.1**
      - Server CHALLENGE_MESSAGE construction
    * - **[MS-NLMP] §3.2.5.1.2**
      - Anonymous authentication detection
    * - **[MS-NLMP] §3.3.1**
      - NTLMv1 ``ComputeResponse``
    * - **[MS-NLMP] §3.3.2**
      - NTLMv2 ``ComputeResponse`` (MsvAvTimestamp rule 7)
    * - **KB976918**
      - Extended Protection / CBT authentication failures
    * - **KB239869**
      - NTLM 2 authentication enablement
