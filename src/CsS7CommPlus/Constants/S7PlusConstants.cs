using System.Collections.Generic;

namespace CsS7CommPlus.Constants
{
    /// <summary>
    /// S7comm-plus protocol constants (VM106 / S7-1200 format specification).
    /// Direct port of the Python module s7p_const.py.
    /// </summary>
    public static class S7PlusConstants
    {
        // --- transport -----------------------------------------------------
        /// <summary>ISO-on-TCP (RFC 1006) server port.</summary>
        public const int IsoTcpPort = 102;
        /// <summary>TPKT version byte.</summary>
        public const byte TpktVersion = 0x03;

        // COTP PDU types
        /// <summary>COTP Connect Request.</summary>
        public const byte CotpCr = 0xE0;
        /// <summary>COTP Connect Confirm.</summary>
        public const byte CotpCc = 0xD0;
        /// <summary>COTP Data (DT).</summary>
        public const byte CotpDt = 0xF0;

        // COTP parameter codes
        /// <summary>COTP source-TSAP parameter.</summary>
        public const byte CotpParamSrcTsap = 0xC1;
        /// <summary>COTP destination-TSAP parameter.</summary>
        public const byte CotpParamDstTsap = 0xC2;
        /// <summary>COTP TPDU-size parameter.</summary>
        public const byte CotpParamTpduSize = 0xC0;

        /// <summary>Destination TSAP for native S7-1200 HMI communication (spec §5).</summary>
        public const string DestTsap = "SIMATIC-ROOT-HMI";
        /// <summary>Default client access-point name (configurable; spec §5).</summary>
        public const string DefaultSrcTsap = "SIMATIC-HMI";

        /// <summary>TPDU size parameter value for 2^10 = 1024 bytes.</summary>
        public const byte TpduSize1024 = 0x0A;

        // --- S7comm-plus framing (spec §6) ---------------------------------
        /// <summary>S7comm-plus protocol id.</summary>
        public const byte S7pProtocolId = 0x72;
        /// <summary>Protocol version 1 (CreateObject / session).</summary>
        public const byte Version1 = 0x01;
        /// <summary>Protocol version 2 (SetMultiVariables key setup).</summary>
        public const byte Version2 = 0x02;
        /// <summary>Protocol version 3 (integrity-protected steady state).</summary>
        public const byte Version3 = 0x03;

        // opcodes (spec Table 7)
        /// <summary>Request opcode.</summary>
        public const byte OpRequest = 0x31;
        /// <summary>Response opcode.</summary>
        public const byte OpResponse = 0x32;
        /// <summary>Notification opcode.</summary>
        public const byte OpNotification = 0x33;

        // function codes (spec Table 16)
        /// <summary>Explore (symbol-tree browse).</summary>
        public const ushort FuncExplore = 0x04BB;
        /// <summary>CreateObject (session creation).</summary>
        public const ushort FuncCreateObject = 0x04CA;
        /// <summary>DeleteObject.</summary>
        public const ushort FuncDeleteObject = 0x04D4;
        /// <summary>SetVariable (single-variable write).</summary>
        public const ushort FuncSetVariable = 0x04F2;
        /// <summary>Single-variable read.</summary>
        public const ushort FuncReadSingle = 0x04FC;
        /// <summary>GetLink.</summary>
        public const ushort FuncGetLink = 0x0524;
        /// <summary>SetMultiVariables (key setup AND tag writes).</summary>
        public const ushort FuncSetMultiVar = 0x0542;
        /// <summary>GetMultiVariables (batched cyclic read).</summary>
        public const ushort FuncGetMultiVar = 0x054C;
        /// <summary>BeginSequence.</summary>
        public const ushort FuncBeginSequence = 0x0556;
        /// <summary>EndSequence.</summary>
        public const ushort FuncEndSequence = 0x0560;
        /// <summary>Invoke.</summary>
        public const ushort FuncInvoke = 0x056B;
        /// <summary>GetVarSubStreamed.</summary>
        public const ushort FuncGetVarSubStreamed = 0x0586;

        /// <summary>Human-readable function-code names.</summary>
        public static readonly Dictionary<ushort, string> FunctionNames = new Dictionary<ushort, string>
        {
            { FuncExplore, "Explore" },
            { FuncCreateObject, "CreateObject" },
            { FuncDeleteObject, "DeleteObject" },
            { FuncSetVariable, "SetVariable" },
            { FuncReadSingle, "ReadSingle" },
            { FuncGetLink, "GetLink" },
            { FuncSetMultiVar, "SetMultiVariables" },
            { FuncGetMultiVar, "GetMultiVariables" },
            { FuncBeginSequence, "BeginSequence" },
            { FuncEndSequence, "EndSequence" },
            { FuncInvoke, "Invoke" },
            { FuncGetVarSubStreamed, "GetVarSubStreamed" },
        };

        /// <summary>v3 integrity part: length byte 0x20 then a 32-byte digest (spec §6.2).</summary>
        public const byte IntegrityDigestLen = 0x20;

        /// <summary>Write/return success marker (spec §12).</summary>
        public const byte WriteSuccessRetval = 0x34;
    }
}
