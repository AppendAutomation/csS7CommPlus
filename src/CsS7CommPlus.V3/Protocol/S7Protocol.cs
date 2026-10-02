using System.Collections.Generic;
using System.Text;

namespace CsS7CommPlus.V3.Protocol
{
    /// <summary>
    /// S7comm-plus wire constants: framing, opcodes, function codes, the object
    /// model element tags and the well-known object / attribute ids.
    ///
    /// Ported from the MIT-licensed s7commplus Python backend (protocol.py).
    /// </summary>
    public static class S7Protocol
    {
        /// <summary>Protocol id byte (0x32 is the legacy S7comm).</summary>
        public const byte ProtocolId = 0x72;

        /// <summary>Client access point; the PLC side is the ASCII TSAP below.</summary>
        public const ushort LocalTsap = 0x0600;

        /// <summary>Remote TSAP, the 16-byte ASCII string "SIMATIC-ROOT-HMI".</summary>
        public static readonly byte[] RemoteTsap = Encoding.ASCII.GetBytes("SIMATIC-ROOT-HMI");

        /// <summary>Function codes that advance the read IntegrityId counter.</summary>
        public static readonly HashSet<ushort> ReadFunctionCodes = new HashSet<ushort>
        {
            (ushort)FunctionCode.GetMultiVariables,
            (ushort)FunctionCode.Explore,
            (ushort)FunctionCode.GetVarSubStreamed,
            (ushort)FunctionCode.GetLink,
            (ushort)FunctionCode.GetVariable,
            (ushort)FunctionCode.GetVariablesAddress,
        };

        /// <summary>
        /// Function codes whose requests carry transport flags 0x34 rather than 0x36.
        /// This is a per-request-class split, not a read/write one: the writes
        /// SetVariable, SetMultiVariables and DeleteObject use 0x34 as well.  A
        /// session-setup CreateObject sent with 0x34 makes the PLC reset the
        /// connection, so CreateObject stays at 0x36.
        /// </summary>
        public static readonly HashSet<ushort> Flags34FunctionCodes = new HashSet<ushort>
        {
            (ushort)FunctionCode.DeleteObject,
            (ushort)FunctionCode.Explore,
            (ushort)FunctionCode.GetMultiVariables,
            (ushort)FunctionCode.GetVarSubStreamed,
            (ushort)FunctionCode.SetMultiVariables,
            (ushort)FunctionCode.SetVariable,
        };
    }

    /// <summary>
    /// S7comm-plus protocol versions.  V1 is early S7-1200 FW V4.0; V2 adds
    /// integrity checking and session authentication; V3 adds the public-key
    /// key exchange.  TIA Portal V17+ wraps V2 framing inside TLS 1.3.
    /// </summary>
    public enum ProtocolVersion : byte
    {
        /// <summary>Early S7-1200 firmware; plain session handshake.</summary>
        V1 = 0x01,
        /// <summary>Adds integrity checking and session authentication.</summary>
        V2 = 0x02,
        /// <summary>Adds the public-key key exchange and the keyed frame digest.</summary>
        V3 = 0x03,
        /// <summary>Out-of-band system event frame.</summary>
        SystemEvent = 0xFE,
    }

    /// <summary>The first byte after the frame header.</summary>
    public enum Opcode : byte
    {
        /// <summary>Client request.</summary>
        Request = 0x31,
        /// <summary>Server response.</summary>
        Response = 0x32,
        /// <summary>Unsolicited subscription notification.</summary>
        Notification = 0x33,
        /// <summary>Alternate response opcode seen on older firmware.</summary>
        Response2 = 0x02,
    }

    /// <summary>S7comm-plus function codes.</summary>
    public enum FunctionCode : ushort
    {
        /// <summary>Error reply.</summary>
        Error = 0x04B1,
        /// <summary>Browse the object / symbol tree.</summary>
        Explore = 0x04BB,
        /// <summary>Create an object (session setup, subscriptions).</summary>
        CreateObject = 0x04CA,
        /// <summary>Delete an object.</summary>
        DeleteObject = 0x04D4,
        /// <summary>Write one variable.</summary>
        SetVariable = 0x04F2,
        /// <summary>Read one variable (old S7-1200 firmware only).</summary>
        GetVariable = 0x04FC,
        /// <summary>Add a link.</summary>
        AddLink = 0x0506,
        /// <summary>Remove a link.</summary>
        RemoveLink = 0x051A,
        /// <summary>Get a link.</summary>
        GetLink = 0x0524,
        /// <summary>Write several variables in one request.</summary>
        SetMultiVariables = 0x0542,
        /// <summary>Read several variables in one request.</summary>
        GetMultiVariables = 0x054C,
        /// <summary>Begin a request sequence.</summary>
        BeginSequence = 0x0556,
        /// <summary>End a request sequence.</summary>
        EndSequence = 0x0560,
        /// <summary>Invoke a method.</summary>
        Invoke = 0x056B,
        /// <summary>Write a sub-streamed variable.</summary>
        SetVarSubStreamed = 0x057C,
        /// <summary>Read a sub-streamed variable.</summary>
        GetVarSubStreamed = 0x0586,
        /// <summary>Resolve variable addresses.</summary>
        GetVariablesAddress = 0x0590,
        /// <summary>Abort.</summary>
        Abort = 0x059A,
        /// <summary>Alternate error reply.</summary>
        Error2 = 0x05A9,
        /// <summary>Request the TLS transition (TIA V17+).</summary>
        InitSsl = 0x05B3,
    }

    /// <summary>Element tags of the S7comm-plus tagged object model.</summary>
    public enum ElementId : byte
    {
        /// <summary>Object header follows.</summary>
        StartOfObject = 0xA1,
        /// <summary>End of the current object.</summary>
        TerminatingObject = 0xA2,
        /// <summary>An attribute id plus typed value follows.</summary>
        Attribute = 0xA3,
        /// <summary>A relation follows.</summary>
        Relation = 0xA4,
        /// <summary>Tag description header follows.</summary>
        StartOfTagDescription = 0xA7,
        /// <summary>End of the current tag description.</summary>
        TerminatingTagDescription = 0xA8,
        /// <summary>Variable type list follows.</summary>
        VarTypeList = 0xAB,
        /// <summary>Variable name list follows.</summary>
        VarNameList = 0xAC,
    }

    /// <summary>Well-known object ids used during session establishment.</summary>
    public enum ObjectId : uint
    {
        /// <summary>No object.</summary>
        None = 0,
        /// <summary>Ask the server to allocate a new RID.</summary>
        GetNewRidOnServer = 211,
        /// <summary>Subscriptions class.</summary>
        ClassSubscriptions = 255,
        /// <summary>Server-session container class.</summary>
        ClassServerSessionContainer = 284,
        /// <summary>Server-session container object.</summary>
        ObjectServerSessionContainer = 285,
        /// <summary>Server-session class.</summary>
        ClassServerSession = 287,
        /// <summary>The null server session used to open a session.</summary>
        ObjectNullServerSession = 288,
        /// <summary>Client RID attribute of a server session.</summary>
        ServerSessionClientRid = 300,
        /// <summary>Server-session version attribute, echoed during setup.</summary>
        ServerSessionVersion = 306,
    }

    /// <summary>S7comm-plus wire data types (distinct from the PLC soft data types).</summary>
    public enum DataType : byte
    {
        /// <summary>No value.</summary>
        Null = 0x00,
        /// <summary>Single bit.</summary>
        Bool = 0x01,
        /// <summary>Unsigned 8-bit.</summary>
        USInt = 0x02,
        /// <summary>Unsigned 16-bit.</summary>
        UInt = 0x03,
        /// <summary>Unsigned 32-bit, VLQ encoded.</summary>
        UDInt = 0x04,
        /// <summary>Unsigned 64-bit, VLQ encoded.</summary>
        ULInt = 0x05,
        /// <summary>Signed 8-bit.</summary>
        SInt = 0x06,
        /// <summary>Signed 16-bit.</summary>
        Int = 0x07,
        /// <summary>Signed 32-bit, VLQ encoded.</summary>
        DInt = 0x08,
        /// <summary>Signed 64-bit, VLQ encoded.</summary>
        LInt = 0x09,
        /// <summary>Unsigned 8-bit bit pattern.</summary>
        Byte = 0x0A,
        /// <summary>Unsigned 16-bit bit pattern.</summary>
        Word = 0x0B,
        /// <summary>Unsigned 32-bit bit pattern, fixed width.</summary>
        DWord = 0x0C,
        /// <summary>Unsigned 64-bit bit pattern, fixed width.</summary>
        LWord = 0x0D,
        /// <summary>IEEE single.</summary>
        Real = 0x0E,
        /// <summary>IEEE double.</summary>
        LReal = 0x0F,
        /// <summary>Nanoseconds since 1970 as unsigned 64-bit.</summary>
        Timestamp = 0x10,
        /// <summary>Signed 64-bit nanosecond span, VLQ encoded.</summary>
        Timespan = 0x11,
        /// <summary>Relation id, fixed 32-bit.</summary>
        Rid = 0x12,
        /// <summary>Attribute id, VLQ encoded 32-bit.</summary>
        Aid = 0x13,
        /// <summary>Length-prefixed opaque bytes.</summary>
        Blob = 0x14,
        /// <summary>Length-prefixed UTF-8 text.</summary>
        WString = 0x15,
        /// <summary>Discriminated value.</summary>
        Variant = 0x16,
        /// <summary>Structured value.</summary>
        Struct = 0x17,
        /// <summary>Classic S7 string.</summary>
        S7String = 0x19,
    }

    /// <summary>Well-known ids for S7comm-plus protocol structures and attributes.</summary>
    public static class Ids
    {
        /// <summary>Actual-value sub-area of a data block.</summary>
        public const uint DbValueActual = 2550;

        /// <summary>
        /// Actual-value sub-area for symbolic (LID) access to the controller
        /// areas I/Q/M.  2551 is DB_InitialChanged, not a controller sub-area, and
        /// using it makes the PLC reject every I/Q/M symbolic access.
        /// </summary>
        public const uint ControllerAreaValueActual = 3736;

        /// <summary>SecurityKey struct.</summary>
        public const uint StructSecurityKey = 1800;
        /// <summary>SecurityKey id element.</summary>
        public const uint SecurityKeyId = 1825;
        /// <summary>Session key element.</summary>
        public const uint SessionKey = 1830;

        /// <summary>ObjectQualifier structure.</summary>
        public const uint ObjectQualifier = 1256;
        /// <summary>ObjectQualifier parent RID.</summary>
        public const uint ParentRid = 1257;
        /// <summary>ObjectQualifier composition AID.</summary>
        public const uint CompositionAid = 1258;
        /// <summary>ObjectQualifier key qualifier.</summary>
        public const uint KeyQualifier = 1259;

        /// <summary>Native RID of the I area.</summary>
        public const uint NativeTheIAreaRid = 80;
        /// <summary>Native RID of the Q area.</summary>
        public const uint NativeTheQAreaRid = 81;
        /// <summary>Native RID of the M area.</summary>
        public const uint NativeTheMAreaRid = 82;
        /// <summary>Native RID of the S7 counters.</summary>
        public const uint NativeTheS7CountersRid = 83;
        /// <summary>Native RID of the S7 timers.</summary>
        public const uint NativeTheS7TimersRid = 84;

        /// <summary>Native RID of the PLC program, the Explore root for symbols.</summary>
        public const uint NativeThePlcProgramRid = 3;
        /// <summary>Native RID of the alarm subsystem.</summary>
        public const uint NativeTheAlarmSubsystemRid = 8;
        /// <summary>Native RID of the CPU execution unit.</summary>
        public const uint NativeTheCpuExecUnitRid = 52;

        /// <summary>Attribute 233: the object's variable type name.</summary>
        public const uint ObjectVariableTypeName = 233;
        /// <summary>Attribute 2521: a block's number.</summary>
        public const uint BlockBlockNumber = 2521;
        /// <summary>Attribute 8064: 1 while the CPU is executing, 0 in STOP.</summary>
        public const uint CpuExecUnitExecuting = 8064;
        /// <summary>Attribute 8065: 7 in RUN, 0 in STOP.</summary>
        public const uint CpuExecUnitOperatingMode = 8065;

        /// <summary>TypeInfo class.</summary>
        public const uint ClassTypeInfo = 511;
        /// <summary>OMS type-info container class.</summary>
        public const uint ClassOmsTypeInfoContainer = 534;
        /// <summary>OMS type-info container object.</summary>
        public const uint ObjectOmsTypeInfoContainer = 537;
        /// <summary>Class RID of the PLC program.</summary>
        public const uint PlcProgramClassRid = 2520;
        /// <summary>Class id of a data block in an Explore response.</summary>
        public const uint DbClassRid = 2574;

        /// <summary>Subscriptions class.</summary>
        public const uint ClassSubscriptions = 255;
        /// <summary>Subscription class.</summary>
        public const uint ClassSubscription = 1001;
        /// <summary>Count of notifications the PLC could not send.</summary>
        public const uint SubscriptionMissedSendings = 1002;
        /// <summary>Subscription subsystem error.</summary>
        public const uint SubscriptionSubsystemError = 1003;
        /// <summary>Per-reference trigger mode.</summary>
        public const uint SubscriptionReferenceTriggerMode = 1005;
        /// <summary>Route mode.</summary>
        public const uint SubscriptionRouteMode = 1040;
        /// <summary>Whether the subscription is active.</summary>
        public const uint SubscriptionActive = 1041;
        /// <summary>Reference list of subscribed items.</summary>
        public const uint SubscriptionReferenceList = 1048;
        /// <summary>
        /// How often the PLC samples the subscribed symbols, in milliseconds.
        /// It is a sampling rate, not a change filter: a value that moves more
        /// than once within a cycle is reported once, at its latest value.
        /// </summary>
        public const uint SubscriptionCycleTime = 1049;
        /// <summary>Delay before the first notification.</summary>
        public const uint SubscriptionDelayTime = 1050;
        /// <summary>Whether the subscription is disabled.</summary>
        public const uint SubscriptionDisabled = 1051;
        /// <summary>Notification count.</summary>
        public const uint SubscriptionCount = 1052;
        /// <summary>Credit limit.</summary>
        public const uint SubscriptionCreditLimit = 1053;
        /// <summary>Tick counter.</summary>
        public const uint SubscriptionTicks = 1054;
        /// <summary>Function class id.</summary>
        public const uint SubscriptionFunctionClassId = 1082;

        /// <summary>Session's effective protection level, read via GetVarSubStreamed.</summary>
        public const uint EffectiveProtectionLevel = 1842;
        /// <summary>Session's active protection level.</summary>
        public const uint ActiveProtectionLevel = 1843;

        /// <summary>ServerSessionVersion element carrying the device PAOM string.</summary>
        public const uint SessionVersionSystemPaomString = 319;

        /// <summary>Base of a data block's access area; add the DB number.</summary>
        public const uint DbAccessAreaBase = 0x8A0E0000;

        /// <summary>
        /// Marker for raw/absolute access to non-optimized data: the address path
        /// is this marker, then a zero-based byte offset and a byte size.
        /// </summary>
        public const uint LidOmsStbClassicBlob = 3;
    }

    /// <summary>Protection levels reported by <see cref="Ids.EffectiveProtectionLevel"/>; lower is more privileged.</summary>
    public enum AccessLevel
    {
        /// <summary>No protection configured.</summary>
        None = 0,
        /// <summary>Full access.</summary>
        FullAccess = 1,
        /// <summary>Read access.</summary>
        ReadAccess = 2,
        /// <summary>HMI access.</summary>
        HmiAccess = 3,
        /// <summary>No access.</summary>
        NoAccess = 4,
    }

    /// <summary>Which legitimation (password) exchange the PLC expects.</summary>
    public enum LegitimationType
    {
        /// <summary>Pre-TIA-V17 challenge scheme.</summary>
        Legacy = 1,
        /// <summary>TIA V17+ OMS scheme, keyed from the TLS exporter secret.</summary>
        New = 2,
    }

    /// <summary>Attribute ids used by the legitimation exchange.</summary>
    public static class LegitimationIds
    {
        /// <summary>Session challenge sent by the PLC.</summary>
        public const uint ServerSessionRequest = 303;
        /// <summary>Client response to the session challenge.</summary>
        public const uint ServerSessionResponse = 304;
        /// <summary>Session-setup legitimation written alongside ServerSessionVersion.</summary>
        public const uint SessionSetupLegitimation = 1830;
        /// <summary>Password-authorization challenge response.</summary>
        public const uint Legitimate = 1846;
    }

    /// <summary>
    /// PLC soft data types, as they appear in the symbol table.  These drive the
    /// value decoding for symbolic access.
    /// </summary>
    public enum SoftDataType
    {
        /// <summary>No type.</summary>
        Void = 0,
        /// <summary>BOOL.</summary>
        Bool = 1,
        /// <summary>BYTE.</summary>
        Byte = 2,
        /// <summary>CHAR.</summary>
        Char = 3,
        /// <summary>WORD.</summary>
        Word = 4,
        /// <summary>INT.</summary>
        Int = 5,
        /// <summary>DWORD.</summary>
        DWord = 6,
        /// <summary>DINT.</summary>
        DInt = 7,
        /// <summary>REAL.</summary>
        Real = 8,
        /// <summary>DATE.</summary>
        Date = 9,
        /// <summary>TIME_OF_DAY.</summary>
        TimeOfDay = 10,
        /// <summary>TIME.</summary>
        Time = 11,
        /// <summary>S5TIME.</summary>
        S5Time = 12,
        /// <summary>DATE_AND_TIME.</summary>
        DateAndTime = 14,
        /// <summary>INTERNETTIME.</summary>
        InternetTime = 15,
        /// <summary>ARRAY.</summary>
        Array = 16,
        /// <summary>STRUCT.</summary>
        Struct = 17,
        /// <summary>End-of-struct marker.</summary>
        EndStruct = 18,
        /// <summary>STRING.</summary>
        String = 19,
        /// <summary>POINTER.</summary>
        Pointer = 20,
        /// <summary>Multi-instance FB.</summary>
        MultiFb = 21,
        /// <summary>ANY.</summary>
        Any = 22,
        /// <summary>FB block reference.</summary>
        BlockFb = 23,
        /// <summary>FC block reference.</summary>
        BlockFc = 24,
        /// <summary>DB block reference.</summary>
        BlockDb = 25,
        /// <summary>SDB block reference.</summary>
        BlockSdb = 26,
        /// <summary>COUNTER.</summary>
        Counter = 28,
        /// <summary>TIMER.</summary>
        Timer = 29,
        /// <summary>IEC_COUNTER.</summary>
        IecCounter = 30,
        /// <summary>IEC_TIMER.</summary>
        IecTimer = 31,
        /// <summary>SFB block reference.</summary>
        BlockSfb = 32,
        /// <summary>SFC block reference.</summary>
        BlockSfc = 33,
        /// <summary>OB block reference.</summary>
        BlockOb = 36,
        /// <summary>UDT reference.</summary>
        BlockUdt = 37,
        /// <summary>BBOOL, a bit inside a packed boolean array.</summary>
        BBool = 40,
        /// <summary>LREAL.</summary>
        LReal = 48,
        /// <summary>ULINT.</summary>
        ULInt = 49,
        /// <summary>LINT.</summary>
        LInt = 50,
        /// <summary>LWORD.</summary>
        LWord = 51,
        /// <summary>USINT.</summary>
        USInt = 52,
        /// <summary>UINT.</summary>
        UInt = 53,
        /// <summary>UDINT.</summary>
        UDInt = 54,
        /// <summary>SINT.</summary>
        SInt = 55,
        /// <summary>WCHAR.</summary>
        WChar = 61,
        /// <summary>WSTRING.</summary>
        WString = 62,
        /// <summary>VARIANT.</summary>
        Variant = 63,
        /// <summary>LTIME.</summary>
        LTime = 64,
        /// <summary>LTOD.</summary>
        LTod = 65,
        /// <summary>LDT.</summary>
        Ldt = 66,
        /// <summary>DTL.</summary>
        Dtl = 67,
        /// <summary>REMOTE.</summary>
        Remote = 96,
        /// <summary>AOM identifier.</summary>
        AomIdent = 128,
    }
}
