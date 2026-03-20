
.. _config_smb:

SMB
===

Section ``[SMB]``
------------------

Dementor's SMB server is **auth-capture scaffolding** — it implements exactly
enough of the SMB protocol to complete an NTLM handshake, extract crackable
hashes, and drop the connection.  It does not implement file I/O, named pipes,
DFS, oplocks, or any post-authentication operations beyond minimal tree-connect
scaffolding.

The server accepts connections on port 445 (direct TCP) and optionally port 139
(NetBIOS session service).  It supports SMB1 and SMB2/3 simultaneously,
negotiating the highest common dialect with each client.

.. tip::

    The default configuration is **maximally open** — it accepts every auth type
    from every client version (XP through Windows 11 / Server 2022).  Restrict
    down only when targeting specific environments.


Authentication Paths
--------------------

Every client connection follows one of three authentication paths, determined
by the first byte of the SMB payload and the client's capabilities.

.. list-table::
    :widths: 18 27 27 28
    :header-rows: 1

    * - Property
      - **Path A: SMB1 Extended**
      - **Path B: SMB1 Basic**
      - **Path C: SMB2/3**
    * - Trigger
      - ``0xFF`` + ``FLAGS2_EXTENDED_SECURITY`` set
      - ``0xFF`` + ``FLAGS2_EXTENDED_SECURITY`` **not** set
      - ``0xFE`` (direct SMB2 packet)
    * - Typical clients
      - XP SP3, XP SP0, Server 2003
      - NT 4.0, nmap probes, embedded devices
      - Vista through Win 11, Server 2008–2022
    * - Negotiate response
      - NT LM 0.12 + SPNEGO token + ServerGUID
      - NT LM 0.12 + 8-byte challenge + ServerName + DomainName
      - Selected dialect + SPNEGO token + ServerGUID + negotiate contexts
    * - Session setup structure
      - ``SESSION_SETUP_ANDX`` with ``WordCount=12``; ``SecurityBlob`` carries
        NTLMSSP
      - ``SESSION_SETUP_ANDX`` with ``WordCount=13``; ``OemPassword`` and
        ``UnicodePassword`` carry raw LM/NT hashes directly
      - ``SMB2_SESSION_SETUP``; ``Buffer`` carries SPNEGO(NTLMSSP)
    * - Auth exchange
      - 3 messages: NEGOTIATE |rarr| CHALLENGE |rarr| AUTHENTICATE
      - **1 message**: client sends LM+NT responses in a single
        ``SESSION_SETUP`` (the challenge was in the negotiate response)
      - 3 messages: NEGOTIATE |rarr| CHALLENGE |rarr| AUTHENTICATE
    * - Hash types produced
      - NetNTLMv1-ESS (``NT_len=24``, ``LM=ClientChallenge+Z(16)``)
      - NetNTLMv1 or NetNTLMv1-ESS (``NT_len=24``, ``LM_len=24``); or
        cleartext if the client sends plaintext despite the challenge
      - NetNTLMv2 (``NT_len>24``, blob with AV_PAIRs) + optional LMv2
    * - SPNEGO wrapping
      - Yes (``negTokenInit`` / ``negTokenResp``)
      - No — raw challenge/response at the SMB layer
      - Yes (``negTokenInit`` / ``negTokenResp``)
    * - Code path (``smb.py``)
      - ``handle_smb1_negotiate`` |rarr| ``handle_smb1_session_setup``
        (WC=12) |rarr| ``handle_ntlmssp`` |rarr| ``ntlm.py``
      - ``handle_smb1_negotiate`` |rarr| ``handle_smb1_session_setup``
        (WC=13) |rarr| ``handle_smb1_session_setup_basic`` |rarr|
        ``NTLM_handle_legacy_raw_auth``
      - ``handle_smb2_negotiate`` |rarr| ``handle_smb2_session_setup``
        |rarr| ``handle_ntlmssp`` |rarr| ``ntlm.py``

.. |rarr| unicode:: U+2192

.. note::

    **Paths A and C share the same NTLM processing code** —
    ``handle_ntlmssp()`` dispatches to ``NTLM_handle_negotiate_message``,
    ``NTLM_build_challenge_message``, and ``NTLM_handle_authenticate_message``
    in ``ntlm.py``.  The only difference is transport framing.

    **Path B is completely separate** — there is no NTLMSSP message exchange.
    The 8-byte challenge was sent in the SMB1 negotiate response and the
    client's hashes arrive as raw bytes in a single ``SESSION_SETUP`` request.
    This path uses ``NTLM_handle_legacy_raw_auth``, which feeds into the same
    ``NTLM_to_hashcat`` formatter but bypasses all NTLMSSP parsing.


SMB1-to-SMB2 Upgrade
~~~~~~~~~~~~~~~~~~~~~

When :attr:`AllowSMB1Upgrade` is ``true`` (the default) and :attr:`EnableSMB2`
is ``true``, an SMB1 ``NEGOTIATE`` that includes ``"SMB 2.???"`` or any SMB2
dialect string triggers a protocol transition: the server responds with an
``SMB2_NEGOTIATE_RESPONSE`` and the connection continues as Path C.

In practice, **no modern Windows client uses this path** — Vista and later send
a direct ``0xFE`` SMB2 ``NEGOTIATE`` on port 445.  The upgrade path exists for
transitional-era clients (early Vista/Win7 builds) and third-party SMB stacks.


Client Information Leakage
~~~~~~~~~~~~~~~~~~~~~~~~~~

Each authentication path leaks different client information:

.. list-table::
    :widths: 30 25 25 20
    :header-rows: 1

    * - Field
      - Path A (SMB1 Ext)
      - Path B (SMB1 Basic)
      - Path C (SMB2)
    * - NTLM OS version
      - Yes (VERSION structure)
      - No (no NTLMSSP)
      - Yes (VERSION structure)
    * - NTLM username
      - Yes
      - No (SMB-layer ``AccountName`` instead)
      - Yes
    * - NTLM domain
      - Yes
      - No (SMB-layer ``PrimaryDomain`` instead)
      - Yes
    * - NTLM workstation
      - Yes
      - No
      - Yes
    * - NTLM SPN (``MsvAvTargetName``)
      - No (NTLMv1 — no blob)
      - No
      - Yes (in NTLMv2 blob AV_PAIRs)
    * - NTLM MIC
      - Varies (garbled on XP/Srv2003)
      - No
      - Yes
    * - SMB NativeOS
      - Yes (``SESSION_SETUP`` response strings)
      - Yes (``SESSION_SETUP`` response strings)
      - No (SMB2 has no NativeOS field)
    * - SMB NativeLanMan
      - Yes
      - Yes
      - No
    * - SMB AccountName
      - No (in NTLMSSP instead)
      - Yes (in ``SESSION_SETUP`` data)
      - No (in NTLMSSP instead)
    * - NetBIOS CallingName
      - Port 139 only
      - Port 139 only
      - No (port 445 only)
    * - SMB dialects offered
      - Yes (6 SMB1 dialects)
      - Yes (6 SMB1 dialects)
      - Yes (SMB2 dialect list + capabilities)


Options
-------

Transport and Protocol
~~~~~~~~~~~~~~~~~~~~~~

.. py:currentmodule:: SMB

.. py:attribute:: EnableSMB1
    :type: bool
    :value: true

    *Maps to* :attr:`smb.SMBServerConfig.smb_enable_smb1`

    Accept SMB1 (``0xFF``) packets.  When ``false``, SMB1 packets are silently
    dropped at the transport layer.  SMB1-only clients (XP, Server 2003)
    will connect but receive no challenge and capture no hashes.

    SMB2+ clients are completely unaffected by this setting.

.. py:attribute:: EnableSMB2
    :type: bool
    :value: true

    *Maps to* :attr:`smb.SMBServerConfig.smb_enable_smb2`

    Accept SMB2/3 (``0xFE``) packets.  When ``false``, SMB2/3 packets are
    silently dropped.  All modern clients (Vista through Server 2022) send
    direct SMB2 ``NEGOTIATE`` and will capture no hashes with this disabled.

    SMB1-only clients are completely unaffected by this setting.

    .. warning::

        Setting this to ``false`` loses **all modern clients**.  Only use when
        exclusively targeting legacy SMB1 environments.

.. py:attribute:: AllowSMB1Upgrade
    :type: bool
    :value: true

    *Maps to* :attr:`smb.SMBServerConfig.smb_allow_smb1_upgrade`

    Allow SMB1 ``NEGOTIATE`` requests containing SMB2 dialect strings
    (``"SMB 2.???"`` or ``"SMB 2.002"``) to trigger a protocol transition to
    SMB2.  Requires :attr:`EnableSMB2` to also be ``true``.

    .. note::

        In practice, no modern Windows client uses this upgrade path — they
        all send direct ``0xFE`` SMB2 packets.  This flag only matters for
        transitional-era clients or third-party SMB implementations.

.. py:attribute:: SMB2MinDialect
    :type: str
    :value: "2.002"

    *Maps to* :attr:`smb.SMBServerConfig.smb2_min_dialect`

    Floor for SMB2/3 dialect negotiation.  Clients whose highest dialect is
    below this minimum will receive ``STATUS_NOT_SUPPORTED`` and capture no
    hashes.  Valid values:

    .. list-table::
        :widths: 15 40 45
        :header-rows: 1

        * - Value
          - Dialect
          - Clients excluded when set as minimum
        * - ``"2.002"``
          - SMB 2.002
          - *(none — this is the lowest)*
        * - ``"2.1"``
          - SMB 2.1
          - Vista, Server 2008 (only support 2.002)
        * - ``"3.0"``
          - SMB 3.0
          - Above + Win 7, Server 2008 R2 (max 2.1)
        * - ``"3.0.2"``
          - SMB 3.0.2
          - Same as 3.0 (no additional exclusions)
        * - ``"3.1.1"``
          - SMB 3.1.1
          - Above + Win 8.1, Server 2012 R2 (max 3.0.2)

    SMB1-only clients (XP, Server 2003) are **never affected** by this
    setting — they negotiate via the SMB1 path.

.. py:attribute:: SMB2MaxDialect
    :type: str
    :value: "3.1.1"

    *Maps to* :attr:`smb.SMBServerConfig.smb2_max_dialect`

    Ceiling for SMB2/3 dialect negotiation.  Clients that support higher
    dialects will negotiate down to this value.  Lowering the ceiling does
    **not** exclude any client — all SMB2+ clients support downward
    negotiation.

    Valid values are the same as :attr:`SMB2MinDialect`.

    .. warning::

        Setting ``SMB2MinDialect`` higher than ``SMB2MaxDialect`` creates an
        invalid range.  No SMB2 dialect can be agreed upon and **all SMB2+
        clients** will fail to negotiate.  SMB1-only clients are unaffected.


SMB Identity
~~~~~~~~~~~~

These values appear in SMB1 negotiate and session-setup responses.  They do
**not** affect the NTLM layer (use the ``NTLM.*`` overrides below for that).
No client rejects or changes authentication behavior based on any of these
values.

.. py:attribute:: NetBIOSComputer
    :type: str
    :value: "DEMENTOR"

    *Maps to* :attr:`smb.SMBServerConfig.smb_nb_computer`

    NetBIOS computer name in the SMB1 non-extended negotiate response
    ``ServerName`` field.  Also used as the fallback for
    :attr:`NTLM.NetBIOSComputer` when that is not set.

.. py:attribute:: NetBIOSDomain
    :type: str
    :value: "WORKGROUP"

    *Maps to* :attr:`smb.SMBServerConfig.smb_nb_domain`

    NetBIOS domain name in the SMB1 non-extended negotiate response
    ``DomainName`` field.  Also used as the fallback for
    :attr:`NTLM.NetBIOSDomain` when that is not set.

.. py:attribute:: ServerOS
    :type: str
    :value: "Windows"

    *Maps to* :attr:`smb.SMBServerConfig.smb_server_os`

    ``NativeOS`` string in the SMB1 ``SESSION_SETUP_ANDX`` response.  Only
    visible to SMB1 clients.  SMB2 has no equivalent field.

.. py:attribute:: NativeLanMan
    :type: str
    :value: None (defaults to ServerOS)

    *Maps to* :attr:`smb.SMBServerConfig.smb_native_lanman`

    ``NativeLanMan`` string in the SMB1 ``SESSION_SETUP_ANDX`` response.
    When ``None`` or empty, defaults to the value of :attr:`ServerOS`.


Post-Auth Behaviour
~~~~~~~~~~~~~~~~~~~

.. py:attribute:: CapturesPerConnection
    :type: int
    :value: 0

    *Maps to* :attr:`smb.SMBServerConfig.smb_captures_per_connection`

    Controls multi-credential capture via Windows SSPI retry.

    - ``0`` (default) — multi-credential retry is disabled.  Each capture
      returns the configured :attr:`ErrorCode` immediately.  This is the
      recommended setting for most environments.

    - ``N`` (where N > 0) — the first N-1 captures return
      ``STATUS_ACCOUNT_DISABLED`` (``0xC0000072``), which triggers Windows SSPI
      to retry with a different cached credential (e.g. a service account).
      The Nth capture returns the configured :attr:`ErrorCode` to end the
      session.

    .. note::

        Multi-credential capture only works when the client has **multiple
        cached credentials** and the SSPI layer retries within the **same TCP
        connection**.  If the client has only one credential (the typical case
        for ``dir \\server\share`` loops), setting CPC > 0 has no additional
        effect over CPC = 0.

.. py:attribute:: ErrorCode
    :type: str | int
    :value: "STATUS_SMB_BAD_UID"

    *Maps to* :attr:`smb.SMBServerConfig.smb_error_code`

    NTSTATUS code returned after the final hash capture.  Accepts integer
    codes or string names from ``impacket.nt_errors``.

    .. list-table::
        :widths: 35 65
        :header-rows: 1

        * - Value
          - Effect
        * - ``"STATUS_SMB_BAD_UID"`` (default)
          - Client disconnects cleanly.
        * - ``"STATUS_ACCESS_DENIED"``
          - Client may retry, then disconnects.
        * - ``"STATUS_LOGON_FAILURE"``
          - Client disconnects cleanly.
        * - ``"STATUS_SUCCESS"``
          - Client proceeds to tree connect.  Useful for extending the
            session to capture tree-connect paths.

    The error code is logged at debug level as
    ``S: ErrorCode=0x{code:08x} (final)`` after each capture.


NTLM Overrides
~~~~~~~~~~~~~~~

These options override the global ``[NTLM]`` section for SMB specifically.
The resolution order is: ``[[SMB.Server]]`` |rarr| ``[SMB]`` |rarr|
``[NTLM]`` |rarr| code default.

.. important::

    When setting these in the ``[SMB]`` section, use the ``NTLM.`` prefix
    (e.g. ``NTLM.Challenge``).  Bare names like ``Challenge`` are treated as
    SMB-local keys and **silently ignored** by the NTLM resolution chain.

.. py:attribute:: NTLM.Challenge
    :type: str
    :value: (inherited from [NTLM])

    Per-SMB override for :attr:`NTLM.Challenge`.

    .. seealso:: :ref:`config_ntlm` for accepted formats and behaviour.

.. py:attribute:: NTLM.DisableExtendedSessionSecurity
    :type: bool
    :value: false

    Per-SMB override for :attr:`NTLM.DisableExtendedSessionSecurity`.
    Affects only SMB1 clients that use NTLMv1 — when ``true``, they produce
    bare NetNTLMv1 instead of NetNTLMv1-ESS.  NTLMv2 clients (Vista+) are
    unaffected.

    .. seealso:: :ref:`config_ntlm` for full behavioural details.

.. py:attribute:: NTLM.DisableNTLMv2
    :type: bool
    :value: false

    Per-SMB override for :attr:`NTLM.DisableNTLMv2`.

    .. warning::

        Setting this to ``true`` produces **zero hashes** from all modern
        Windows clients (Vista through Server 2022).  Only SMB1-only clients
        (XP, Server 2003) continue to capture.

    .. seealso:: :ref:`config_ntlm` for full behavioural details.

.. py:attribute:: NTLM.TargetType
    :type: str
    :value: "server"

    Per-SMB override for :attr:`NTLM.TargetType`.  Sets the
    ``NTLMSSP_TARGET_TYPE`` flag in the ``CHALLENGE_MESSAGE``.

    - ``"server"`` — ``TargetName`` is the NetBIOS computer name.
    - ``"domain"`` — ``TargetName`` is the NetBIOS domain name.

    No client changes authentication behavior based on this value.

.. py:attribute:: NTLM.Version
    :type: str
    :value: "0.0.0" (all-zero placeholder)

    Per-SMB override for :attr:`NTLM.Version`.  The VERSION structure in the
    ``CHALLENGE_MESSAGE``, formatted as ``"major.minor.build"`` (e.g.
    ``"10.0.20348"`` for Server 2022).

    No client changes authentication behavior based on this value.

.. py:attribute:: NTLM.NetBIOSComputer
    :type: str
    :value: None (falls back to SMB.NetBIOSComputer)

    AV_PAIR ``MsvAvNbComputerName`` (``0x0001``) in the ``CHALLENGE_MESSAGE``
    ``TargetInfoFields``.  Falls back to :attr:`NetBIOSComputer` when not set.

.. py:attribute:: NTLM.NetBIOSDomain
    :type: str
    :value: None (falls back to SMB.NetBIOSDomain)

    AV_PAIR ``MsvAvNbDomainName`` (``0x0002``).  Falls back to
    :attr:`NetBIOSDomain` when not set.

.. py:attribute:: NTLM.DnsComputer
    :type: str
    :value: None (derived from NetBIOSComputer + DnsDomain)

    AV_PAIR ``MsvAvDnsComputerName`` (``0x0003``).

.. py:attribute:: NTLM.DnsDomain
    :type: str
    :value: None (falls back to SMB.NetBIOSDomain)

    AV_PAIR ``MsvAvDnsDomainName`` (``0x0004``).

.. py:attribute:: NTLM.DnsTree
    :type: str
    :value: None (derived from DnsDomain)

    AV_PAIR ``MsvAvDnsTreeName`` (``0x0005``).  Omitted when the server
    appears to be workgroup-joined (no dot in domain).

.. note::

    No client rejects or changes authentication behavior based on any identity
    string value (NetBIOSComputer, NetBIOSDomain, DnsComputer, DnsDomain,
    DnsTree, ServerOS, NativeLanMan, TargetType, or Version).  These are all
    cosmetic — they change what appears on the wire and in captured hash lines,
    but every tested Windows version (XP through Server 2022) authenticates
    regardless of what values are set, including empty strings.


Server Instances
~~~~~~~~~~~~~~~~

.. py:attribute:: Server
    :type: list

    Each ``[[SMB.Server]]`` entry spawns a listener on the specified port.
    Attributes set in ``[SMB]`` serve as defaults for all instances.

    .. py:attribute:: Server.Port
        :type: int

        *Maps to* :attr:`smb.SMBServerConfig.smb_port`

        The TCP port to listen on.  **Required** — must be specified in each
        ``[[SMB.Server]]`` block.

        Standard ports:

        - **445** — direct TCP transport (used by all modern clients)
        - **139** — NetBIOS session service (used by XP/Server 2003 in
          addition to port 445; leaks NetBIOS CallingName)


SMB 3.1.1 Negotiate Contexts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the negotiated dialect is SMB 3.1.1, the ``SMB2_NEGOTIATE_RESPONSE``
includes three negotiate contexts:

.. list-table::
    :widths: 35 65
    :header-rows: 1

    * - Context
      - Content
    * - ``SMB2_PREAUTH_INTEGRITY_CAPABILITIES``
      - SHA-512 integrity algorithm with a random 32-byte salt.
    * - ``SMB2_ENCRYPTION_CAPABILITIES``
      - Echoes the client's preferred cipher (default: AES-128-GCM).
    * - ``SMB2_SIGNING_CAPABILITIES``
      - Echoes the client's preferred signing algorithm (default: AES-CMAC).

Dementor does not implement signing, sealing, or encryption — these contexts
are echoed to keep the handshake alive through hash capture.


Default Configuration
---------------------

.. code-block:: toml
    :linenos:
    :caption: Minimal SMB configuration (all options at defaults)

    [SMB]
    EnableSMB1 = true
    EnableSMB2 = true
    AllowSMB1Upgrade = true
    SMB2MinDialect = "2.002"
    SMB2MaxDialect = "3.1.1"
    NetBIOSComputer = "DEMENTOR"
    NetBIOSDomain = "WORKGROUP"
    ServerOS = "Windows"
    # NativeLanMan defaults to ServerOS when not set
    CapturesPerConnection = 0
    ErrorCode = "STATUS_SMB_BAD_UID"

    # NTLM overrides (use NTLM. prefix in [SMB] section):
    # NTLM.Challenge = "ascii:TESTCHAL"
    # NTLM.DisableExtendedSessionSecurity = false
    # NTLM.DisableNTLMv2 = false
    # NTLM.TargetType = "server"
    # NTLM.Version = "10.0.20348"
    # NTLM.NetBIOSComputer = "MYSERVER"
    # NTLM.NetBIOSDomain = "MYDOMAIN"
    # NTLM.DnsComputer = "myserver.mydomain.local"
    # NTLM.DnsDomain = "mydomain.local"
    # NTLM.DnsTree = "mydomain.local"

    [[SMB.Server]]
    Port = 445

    [[SMB.Server]]
    Port = 139


Spec References
---------------

.. list-table::
    :widths: 20 80
    :header-rows: 1

    * - Document
      - Covers
    * - **[MS-SMB]**
      - SMB1 protocol extensions (NT LM 0.12 dialect)
    * - **[MS-SMB2]**
      - SMB 2.x and 3.x protocol
    * - **[MS-NLMP]**
      - NTLM authentication protocol
    * - **[MS-CIFS]**
      - Original SMB1/CIFS (inherited by [MS-SMB] for non-extended structures)
    * - **[MS-SPNG]**
      - SPNEGO / GSS-API negotiation
