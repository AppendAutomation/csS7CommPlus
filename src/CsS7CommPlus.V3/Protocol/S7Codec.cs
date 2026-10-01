using System;
using System.Collections.Generic;
using System.Text;

namespace CsS7CommPlus.V3.Protocol
{
    /// <summary>
    /// Serialization for the S7comm-plus wire format: frame and request headers,
    /// type-tagged values, item addresses and the PValue decoder.
    ///
    /// Ported from the MIT-licensed s7commplus Python backend (codec.py).
    /// </summary>
    public static class S7Codec
    {
        /// <summary>Encode the 4-byte frame header: protocol id, version, data length.</summary>
        public static byte[] EncodeHeader(ProtocolVersion version, int dataLength) => new[]
        {
            S7Protocol.ProtocolId,
            (byte)version,
            (byte)((dataLength >> 8) & 0xFF),
            (byte)(dataLength & 0xFF),
        };

        /// <summary>Decode the frame header; returns the bytes consumed (always 4).</summary>
        public static int DecodeHeader(byte[] data, int offset, out ProtocolVersion version, out int dataLength)
        {
            if (data.Length - offset < 4)
                throw new S7ProtocolException("Not enough data for an S7comm-plus header");
            if (data[offset] != S7Protocol.ProtocolId)
                throw new S7ProtocolException($"Invalid protocol id 0x{data[offset]:X2}, expected 0x{S7Protocol.ProtocolId:X2}");

            version = (ProtocolVersion)data[offset + 1];
            dataLength = (data[offset + 2] << 8) | data[offset + 3];
            return 4;
        }

        /// <summary>
        /// Encode the 14-byte request header that follows the frame header:
        /// opcode, reserved, function code, reserved, sequence number, session id,
        /// transport flags.  Responses carry a 10-byte header with no session id.
        /// </summary>
        public static byte[] EncodeRequestHeader(ushort functionCode, ushort sequenceNumber,
                                                 uint sessionId = 0, byte transportFlags = 0x36)
        {
            var h = new byte[14];
            h[0] = (byte)Opcode.Request;
            h[1] = 0; h[2] = 0;
            h[3] = (byte)(functionCode >> 8); h[4] = (byte)functionCode;
            h[5] = 0; h[6] = 0;
            h[7] = (byte)(sequenceNumber >> 8); h[8] = (byte)sequenceNumber;
            h[9] = (byte)(sessionId >> 24); h[10] = (byte)(sessionId >> 16);
            h[11] = (byte)(sessionId >> 8); h[12] = (byte)sessionId;
            h[13] = transportFlags;
            return h;
        }

        /// <summary>Length of the response header; responses carry no session id.</summary>
        public const int ResponseHeaderLength = 10;

        // --- big-endian primitives -----------------------------------------

        /// <summary>Read a big-endian unsigned 16-bit value.</summary>
        public static ushort ReadUInt16(byte[] data, int offset) => (ushort)((data[offset] << 8) | data[offset + 1]);

        /// <summary>Read a big-endian unsigned 32-bit value.</summary>
        public static uint ReadUInt32(byte[] data, int offset) =>
            ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16) | ((uint)data[offset + 2] << 8) | data[offset + 3];

        /// <summary>Read a big-endian unsigned 64-bit value.</summary>
        public static ulong ReadUInt64(byte[] data, int offset)
        {
            ulong v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | data[offset + i];
            return v;
        }

        /// <summary>Append a big-endian unsigned 16-bit value.</summary>
        public static void AppendUInt16(List<byte> buffer, ushort value)
        {
            buffer.Add((byte)(value >> 8)); buffer.Add((byte)value);
        }

        /// <summary>Append a big-endian unsigned 32-bit value.</summary>
        public static void AppendUInt32(List<byte> buffer, uint value)
        {
            buffer.Add((byte)(value >> 24)); buffer.Add((byte)(value >> 16));
            buffer.Add((byte)(value >> 8)); buffer.Add((byte)value);
        }

        /// <summary>Append a big-endian unsigned 64-bit value.</summary>
        public static void AppendUInt64(List<byte> buffer, ulong value)
        {
            for (int i = 7; i >= 0; i--) buffer.Add((byte)(value >> (i * 8)));
        }

        /// <summary>Copy a range out of a buffer, clamped to its end.</summary>
        public static byte[] Slice(byte[] data, int offset, int length)
        {
            if (offset < 0) offset = 0;
            if (offset >= data.Length) return new byte[0];
            if (offset + length > data.Length) length = data.Length - offset;
            if (length <= 0) return new byte[0];
            var outBytes = new byte[length];
            Array.Copy(data, offset, outBytes, 0, length);
            return outBytes;
        }

        // --- typed values ---------------------------------------------------

        /// <summary>
        /// Encode a value behind its <see cref="DataType"/> tag, the form used for
        /// attribute values in the object model.
        /// </summary>
        public static byte[] EncodeTypedValue(DataType datatype, object? value)
        {
            var o = new List<byte> { (byte)datatype };
            switch (datatype)
            {
                case DataType.Null:
                    break;
                case DataType.Bool:
                    o.Add(Convert.ToBoolean(value) ? (byte)1 : (byte)0);
                    break;
                case DataType.USInt:
                case DataType.Byte:
                    o.Add(Convert.ToByte(value));
                    break;
                case DataType.UInt:
                case DataType.Word:
                    AppendUInt16(o, Convert.ToUInt16(value));
                    break;
                case DataType.UDInt:
                    Vlq.AppendUInt32(o, Convert.ToUInt32(value));
                    break;
                case DataType.DWord:
                    AppendUInt32(o, Convert.ToUInt32(value));       // fixed width, not VLQ
                    break;
                case DataType.ULInt:
                    Vlq.AppendUInt64(o, Convert.ToUInt64(value));
                    break;
                case DataType.LWord:
                    AppendUInt64(o, Convert.ToUInt64(value));       // fixed width, not VLQ
                    break;
                case DataType.SInt:
                    o.Add(unchecked((byte)Convert.ToSByte(value)));
                    break;
                case DataType.Int:
                    AppendUInt16(o, unchecked((ushort)Convert.ToInt16(value)));
                    break;
                case DataType.DInt:
                    o.AddRange(Vlq.EncodeInt32(Convert.ToInt32(value)));
                    break;
                case DataType.LInt:
                case DataType.Timespan:
                    o.AddRange(Vlq.EncodeInt64(Convert.ToInt64(value)));
                    break;
                case DataType.Real:
                    AppendUInt32(o, BitConverter.ToUInt32(Reverse(BitConverter.GetBytes(Convert.ToSingle(value))), 0));
                    break;
                case DataType.LReal:
                    AppendUInt64(o, BitConverter.ToUInt64(Reverse(BitConverter.GetBytes(Convert.ToDouble(value))), 0));
                    break;
                case DataType.Timestamp:
                    AppendUInt64(o, Convert.ToUInt64(value));
                    break;
                case DataType.Rid:
                    AppendUInt32(o, Convert.ToUInt32(value));
                    break;
                case DataType.Aid:
                    Vlq.AppendUInt32(o, Convert.ToUInt32(value));
                    break;
                case DataType.WString:
                    {
                        var encoded = Encoding.UTF8.GetBytes(Convert.ToString(value) ?? string.Empty);
                        Vlq.AppendUInt32(o, (uint)encoded.Length);
                        o.AddRange(encoded);
                        break;
                    }
                case DataType.Blob:
                    {
                        var raw = (byte[])(value ?? new byte[0]);
                        Vlq.AppendUInt32(o, (uint)raw.Length);
                        o.AddRange(raw);
                        break;
                    }
                default:
                    throw new S7ProtocolException($"Unsupported DataType for encoding: 0x{(byte)datatype:X2}");
            }
            return o.ToArray();
        }

        private static byte[] Reverse(byte[] b)
        {
            if (BitConverter.IsLittleEndian) Array.Reverse(b);
            return b;
        }

        /// <summary>
        /// Encode the fixed ObjectQualifier structure appended to
        /// GetMultiVariables and SetMultiVariables requests.  TIA Portal sets the
        /// key qualifier to the current sequence number.  V1-initial sessions use a
        /// fixed-width key qualifier; V2 uses a VLQ plus a terminator byte.
        /// </summary>
        public static byte[] EncodeObjectQualifier(uint keyQualifier = 0,
                                                   ProtocolVersion protocolVersion = ProtocolVersion.V2)
        {
            var o = new List<byte>();
            AppendUInt32(o, Ids.ObjectQualifier);

            // ParentRID = RID(0)
            Vlq.AppendUInt32(o, Ids.ParentRid);
            o.Add(0x00); o.Add((byte)DataType.Rid); AppendUInt32(o, 0);

            // CompositionAID = AID(0)
            Vlq.AppendUInt32(o, Ids.CompositionAid);
            o.Add(0x00); o.Add((byte)DataType.Aid); Vlq.AppendUInt32(o, 0);

            // KeyQualifier = UDInt(keyQualifier)
            Vlq.AppendUInt32(o, Ids.KeyQualifier);
            o.Add(0x00); o.Add((byte)DataType.UDInt);
            if (protocolVersion == ProtocolVersion.V1)
            {
                AppendUInt32(o, keyQualifier);
            }
            else
            {
                Vlq.AppendUInt32(o, keyQualifier);
                o.Add(0x00);
            }
            return o.ToArray();
        }

        /// <summary>
        /// Encode an ItemAddress for symbolic variable access and return the
        /// number of VLQ fields it contributes to the request's field count.
        /// </summary>
        public static byte[] EncodeItemAddress(uint accessArea, uint accessSubArea,
                                               IReadOnlyList<uint>? lids, out int fieldCount,
                                               uint symbolCrc = 0)
        {
            var list = lids ?? (IReadOnlyList<uint>)new uint[0];
            var o = new List<byte>();
            Vlq.AppendUInt32(o, symbolCrc);
            Vlq.AppendUInt32(o, accessArea);
            Vlq.AppendUInt32(o, (uint)(list.Count + 1));    // +1 for the sub-area
            Vlq.AppendUInt32(o, accessSubArea);
            foreach (var lid in list) Vlq.AppendUInt32(o, lid);
            fieldCount = 4 + list.Count;
            return o.ToArray();
        }

        /// <summary>
        /// Encode already-serialized big-endian value bytes as a PValue with an
        /// explicit type.  Fixed-width types are length-checked, and the types the
        /// wire sends as VLQ are re-encoded from the big-endian input.
        /// </summary>
        public static byte[] EncodePValueTyped(DataType datatype, byte[] data)
        {
            var fixedSizes = FixedPValueSizes;
            if (fixedSizes.TryGetValue(datatype, out int expected) && data.Length != expected)
                throw new S7ProtocolException($"{datatype} requires {expected} encoded bytes, got {data.Length}");
            if (datatype == DataType.Null && data.Length > 0)
                throw new S7ProtocolException("NULL requires an empty value");

            var o = new List<byte> { 0x00, (byte)datatype };

            if (datatype == DataType.Blob)
            {
                Vlq.AppendUInt32(o, 0);                     // BlobRootId
                Vlq.AppendUInt32(o, (uint)data.Length);
            }
            else if (datatype == DataType.WString || datatype == DataType.S7String)
            {
                Vlq.AppendUInt32(o, (uint)data.Length);
            }

            switch (datatype)
            {
                case DataType.UDInt:
                case DataType.Aid:
                    Vlq.AppendUInt32(o, (uint)BigEndianToUInt64(data));
                    break;
                case DataType.ULInt:
                    Vlq.AppendUInt64(o, BigEndianToUInt64(data));
                    break;
                case DataType.DInt:
                    o.AddRange(Vlq.EncodeInt32((int)BigEndianToInt64(data)));
                    break;
                case DataType.LInt:
                case DataType.Timespan:
                    o.AddRange(Vlq.EncodeInt64(BigEndianToInt64(data)));
                    break;
                default:
                    o.AddRange(data);
                    break;
            }
            return o.ToArray();
        }

        private static readonly Dictionary<DataType, int> FixedPValueSizes = new Dictionary<DataType, int>
        {
            { DataType.Bool, 1 }, { DataType.USInt, 1 }, { DataType.Byte, 1 }, { DataType.SInt, 1 },
            { DataType.UInt, 2 }, { DataType.Word, 2 }, { DataType.Int, 2 },
            { DataType.UDInt, 4 }, { DataType.DWord, 4 }, { DataType.DInt, 4 }, { DataType.Real, 4 },
            { DataType.ULInt, 8 }, { DataType.LWord, 8 }, { DataType.LInt, 8 }, { DataType.LReal, 8 },
            { DataType.Timestamp, 8 }, { DataType.Timespan, 8 },
            { DataType.Rid, 4 }, { DataType.Aid, 4 },
        };

        private static ulong BigEndianToUInt64(byte[] data)
        {
            ulong v = 0;
            foreach (var b in data) v = (v << 8) | b;
            return v;
        }

        private static long BigEndianToInt64(byte[] data)
        {
            if (data.Length == 0) return 0;
            long v = (sbyte)data[0];
            for (int i = 1; i < data.Length; i++) v = (v << 8) | data[i];
            return v;
        }

        /// <summary>Fixed byte size of a PValue array element, or 0 when VLQ encoded.</summary>
        public static int PValueElementSize(byte datatype)
        {
            switch ((DataType)datatype)
            {
                case DataType.Bool:
                case DataType.USInt:
                case DataType.Byte:
                case DataType.SInt:
                    return 1;
                case DataType.UInt:
                case DataType.Word:
                case DataType.Int:
                    return 2;
                case DataType.Real:
                case DataType.Rid:
                    return 4;
                case DataType.LReal:
                case DataType.Timestamp:
                    return 8;
                default:
                    return 0;
            }
        }

        /// <summary>
        /// Decode a PValue to its raw big-endian bytes, whatever its type.  Scalars,
        /// arrays, blobs, strings and both struct transmission forms are handled.
        /// </summary>
        public static byte[] DecodePValueToBytes(byte[] data, int offset, out int consumed)
        {
            if (offset + 2 > data.Length) throw new S7ProtocolException("Not enough data for a PValue header");

            byte flags = data[offset];
            byte datatype = data[offset + 1];
            consumed = 2;

            bool isArray = (flags & 0x10) != 0;

            if (isArray)
            {
                uint count = Vlq.DecodeUInt32(data, offset + consumed, out int c);
                consumed += c;
                int elemSize = PValueElementSize(datatype);
                if (elemSize > 0)
                {
                    var raw = Slice(data, offset + consumed, (int)count * elemSize);
                    consumed += (int)count * elemSize;
                    return raw;
                }

                var acc = new List<byte>();
                for (uint i = 0; i < count; i++)
                {
                    uint val = Vlq.DecodeUInt32(data, offset + consumed, out int ec);
                    consumed += ec;
                    acc.AddRange(Vlq.EncodeUInt32(val));
                }
                return acc.ToArray();
            }

            switch ((DataType)datatype)
            {
                case DataType.Null:
                    return new byte[0];

                case DataType.Bool:
                case DataType.USInt:
                case DataType.Byte:
                case DataType.SInt:
                    {
                        var raw = Slice(data, offset + consumed, 1);
                        consumed += 1;
                        return raw;
                    }

                case DataType.UInt:
                case DataType.Word:
                case DataType.Int:
                    {
                        var raw = Slice(data, offset + consumed, 2);
                        consumed += 2;
                        return raw;
                    }

                case DataType.UDInt:
                    {
                        uint val = Vlq.DecodeUInt32(data, offset + consumed, out int c);
                        consumed += c;
                        return new[] { (byte)(val >> 24), (byte)(val >> 16), (byte)(val >> 8), (byte)val };
                    }

                case DataType.DWord:
                case DataType.Real:
                case DataType.Rid:
                    {
                        var raw = Slice(data, offset + consumed, 4);   // fixed width, not VLQ
                        consumed += 4;
                        return raw;
                    }

                case DataType.DInt:
                    {
                        int val = Vlq.DecodeInt32(data, offset + consumed, out int c);
                        consumed += c;
                        uint u = unchecked((uint)val);
                        return new[] { (byte)(u >> 24), (byte)(u >> 16), (byte)(u >> 8), (byte)u };
                    }

                case DataType.LReal:
                case DataType.LWord:
                case DataType.Timestamp:
                    {
                        var raw = Slice(data, offset + consumed, 8);   // fixed width, not VLQ
                        consumed += 8;
                        return raw;
                    }

                case DataType.ULInt:
                    {
                        ulong val = Vlq.DecodeUInt64(data, offset + consumed, out int c);
                        consumed += c;
                        var o = new List<byte>(8);
                        AppendUInt64(o, val);
                        return o.ToArray();
                    }

                case DataType.LInt:
                case DataType.Timespan:
                    {
                        long val = Vlq.DecodeInt64(data, offset + consumed, out int c);
                        consumed += c;
                        var o = new List<byte>(8);
                        AppendUInt64(o, unchecked((ulong)val));
                        return o.ToArray();
                    }

                case DataType.Aid:
                    {
                        uint val = Vlq.DecodeUInt32(data, offset + consumed, out int c);
                        consumed += c;
                        return new[] { (byte)(val >> 24), (byte)(val >> 16), (byte)(val >> 8), (byte)val };
                    }

                case DataType.Blob:
                    {
                        Vlq.DecodeUInt32(data, offset + consumed, out int c1);   // BlobRootId
                        consumed += c1;
                        uint length = Vlq.DecodeUInt32(data, offset + consumed, out int c2);
                        consumed += c2;
                        var raw = Slice(data, offset + consumed, (int)length);
                        consumed += (int)length;
                        return raw;
                    }

                case DataType.WString:
                case DataType.S7String:
                    {
                        uint length = Vlq.DecodeUInt32(data, offset + consumed, out int c);
                        consumed += c;
                        var raw = Slice(data, offset + consumed, (int)length);
                        consumed += (int)length;
                        return raw;
                    }

                case DataType.Struct:
                    return DecodeStructToBytes(data, offset, ref consumed);

                default:
                    throw new S7ProtocolException($"Unsupported PValue datatype: 0x{datatype:X2}");
            }
        }

        /// <summary>
        /// Decode a struct PValue.  A packed struct — the form used for system
        /// datatypes such as DTL and for optimized-DB structs — sends its members
        /// as one opaque blob, recognised by the struct id falling in
        /// 0x90000000..0x9FFFFFFF or 0x02000000..0x02FFFFFF; its bytes are returned
        /// verbatim for the caller to interpret against the member layout.  A
        /// normal struct sends members as [VLQ key][PValue] until a zero key.
        /// </summary>
        private static byte[] DecodeStructToBytes(byte[] data, int offset, ref int consumed)
        {
            uint structId = ReadUInt32(data, offset + consumed);     // fixed UInt32, not VLQ
            consumed += 4;

            if ((structId > 0x90000000 && structId < 0x9FFFFFFF) ||
                (structId > 0x02000000 && structId < 0x02FFFFFF))
            {
                consumed += 8;                                       // packed-struct interface timestamp
                uint transportFlags = Vlq.DecodeUInt32(data, offset + consumed, out int cf);
                consumed += cf;
                uint count = Vlq.DecodeUInt32(data, offset + consumed, out int cc);
                consumed += cc;
                if ((transportFlags & 0x400) != 0)                   // Count2Present
                {
                    count = Vlq.DecodeUInt32(data, offset + consumed, out int cc2);
                    consumed += cc2;
                }
                var raw = Slice(data, offset + consumed, (int)count);
                consumed += (int)count;
                return raw;
            }

            var acc = new List<byte>();
            uint key = Vlq.DecodeUInt32(data, offset + consumed, out int ck);
            consumed += ck;
            while (key > 0)
            {
                var member = DecodePValueToBytes(data, offset + consumed, out int cm);
                consumed += cm;
                acc.AddRange(member);
                key = Vlq.DecodeUInt32(data, offset + consumed, out int ck2);
                consumed += ck2;
            }
            return acc.ToArray();
        }

        /// <summary>
        /// Step over a typed value in the object tree and return the new offset.
        /// Used while scanning attributes that are not of interest.
        /// </summary>
        public static int SkipTypedValue(byte[] data, int offset, byte datatype, byte flags)
        {
            bool isArray = (flags & 0x10) != 0;

            if (isArray)
            {
                if (offset >= data.Length) return offset;
                uint count = Vlq.DecodeUInt32(data, offset, out int c);
                offset += c;
                int elemSize = PValueElementSize(datatype);
                if (elemSize > 0) return offset + (int)count * elemSize;
                for (uint i = 0; i < count; i++)
                {
                    if (offset >= data.Length) break;
                    Vlq.DecodeUInt32(data, offset, out int ec);
                    offset += ec;
                }
                return offset;
            }

            switch ((DataType)datatype)
            {
                case DataType.Null:
                    return offset;
                case DataType.Bool:
                case DataType.USInt:
                case DataType.Byte:
                case DataType.SInt:
                    return offset + 1;
                case DataType.UInt:
                case DataType.Word:
                case DataType.Int:
                    return offset + 2;
                case DataType.UDInt:
                case DataType.Aid:
                case DataType.DInt:
                    {
                        Vlq.DecodeUInt32(data, offset, out int c);
                        return offset + c;
                    }
                case DataType.DWord:
                case DataType.Real:
                case DataType.Rid:
                    return offset + 4;
                case DataType.ULInt:
                case DataType.LInt:
                case DataType.Timespan:
                    {
                        Vlq.DecodeUInt64(data, offset, out int c);
                        return offset + c;
                    }
                case DataType.LWord:
                case DataType.LReal:
                case DataType.Timestamp:
                    return offset + 8;
                case DataType.Blob:
                    {
                        Vlq.DecodeUInt32(data, offset, out int c1);   // BlobRootId
                        offset += c1;
                        uint length = Vlq.DecodeUInt32(data, offset, out int c2);
                        return offset + c2 + (int)length;
                    }
                case DataType.WString:
                case DataType.S7String:
                    {
                        uint length = Vlq.DecodeUInt32(data, offset, out int c);
                        return offset + c + (int)length;
                    }
                case DataType.Struct:
                    {
                        // Normal-mode struct: UInt32 struct id, then [VLQ key][typed value]
                        // members, ended by a 0x00 terminator (keys always set the high bit).
                        offset += 4;
                        while (offset < data.Length)
                        {
                            if (data[offset] == 0x00) { offset += 1; break; }
                            Vlq.DecodeUInt32(data, offset, out int ck);
                            offset += ck;
                            if (offset + 2 > data.Length) break;
                            byte subFlags = data[offset];
                            byte subType = data[offset + 1];
                            offset += 2;
                            offset = SkipTypedValue(data, offset, subType, subFlags);
                        }
                        return offset;
                    }
                default:
                    return offset;      // unknown type: cannot skip reliably
            }
        }

        /// <summary>
        /// Parse a CreateObject response body — the part after the 10-byte response
        /// header — into its return value and object ids.  The usable session id is
        /// the first object id, not the header's session-id field.
        /// </summary>
        public static List<uint> ParseCreateObjectSessionId(byte[] body, out int offset, out ulong returnValue)
        {
            returnValue = Vlq.DecodeUInt64(body, 0, out int consumed);
            offset = consumed;
            int objCount = offset < body.Length ? body[offset] : 0;
            offset += 1;

            var objectIds = new List<uint>();
            for (int i = 0; i < objCount; i++)
            {
                uint oid = Vlq.DecodeUInt32(body, offset, out int c);
                offset += c;
                objectIds.Add(oid);
            }
            return objectIds;
        }

        /// <summary>Attributes lifted out of a CreateObject response object tree.</summary>
        public class CreateObjectAttributes
        {
            /// <summary>Attribute 306, the raw typed value echoed back during session setup.</summary>
            public byte[]? ServerSessionVersion { get; set; }
            /// <summary>Attribute 233 as "FF:HHHHHHHHHHHHHHHH" when the PLC uses SessionKey auth.</summary>
            public string? PublicKeyFingerprint { get; set; }
            /// <summary>Attribute 303, the 20-byte session challenge on V1-initial PLCs.</summary>
            public byte[]? SessionChallenge { get; set; }
        }

        /// <summary>
        /// Scan a CreateObject response payload for the session-setup attributes:
        /// ServerSessionVersion (306), the public-key fingerprint (233) and the
        /// session challenge (303).
        /// </summary>
        public static CreateObjectAttributes ParseCreateObjectAttributes(byte[] payload)
        {
            var result = new CreateObjectAttributes();
            int offset = 0;

            while (offset < payload.Length)
            {
                byte tag = payload[offset];

                if (tag == (byte)ElementId.Attribute)
                {
                    offset += 1;
                    if (offset >= payload.Length) break;
                    uint attrId = Vlq.DecodeUInt32(payload, offset, out int c);
                    offset += c;

                    if (offset + 2 > payload.Length) break;
                    byte flags = payload[offset];
                    byte datatype = payload[offset + 1];

                    if (attrId == (uint)ObjectId.ServerSessionVersion)
                    {
                        int valueStart = offset;
                        int end = SkipTypedValue(payload, offset + 2, datatype, flags);
                        result.ServerSessionVersion = Slice(payload, valueStart, end - valueStart);
                        offset = end;
                    }
                    else if (attrId == Ids.ObjectVariableTypeName && datatype == (byte)DataType.WString)
                    {
                        offset += 2;
                        uint length = Vlq.DecodeUInt32(payload, offset, out int cl);
                        offset += cl;
                        var raw = Slice(payload, offset, (int)length);
                        offset += (int)length;
                        try
                        {
                            string text = Encoding.UTF8.GetString(raw);
                            if (text.Length == 19 && text[2] == ':') result.PublicKeyFingerprint = text;
                        }
                        catch (ArgumentException) { /* not a fingerprint */ }
                    }
                    else if (attrId == LegitimationIds.ServerSessionRequest && result.SessionChallenge == null)
                    {
                        bool isArray = (flags & 0x10) != 0;
                        offset += 2;
                        if (isArray && datatype == (byte)DataType.USInt)
                        {
                            uint count = Vlq.DecodeUInt32(payload, offset, out int cc);
                            offset += cc;
                            result.SessionChallenge = Slice(payload, offset, (int)count);
                            offset += (int)count;
                        }
                        else
                        {
                            offset = SkipTypedValue(payload, offset, datatype, flags);
                        }
                    }
                    else
                    {
                        offset = SkipTypedValue(payload, offset + 2, datatype, flags);
                    }
                }
                else if (tag == (byte)ElementId.StartOfObject)
                {
                    offset += 1;
                    if (offset + 4 > payload.Length) break;
                    offset += 4;
                    for (int i = 0; i < 3; i++)
                    {
                        Vlq.DecodeUInt32(payload, offset, out int c);
                        offset += c;
                    }
                }
                else
                {
                    offset += 1;        // terminator, padding or an element we ignore
                }
            }
            return result;
        }

        /// <summary>
        /// Replace element 319 of a captured ServerSessionVersion struct with an
        /// empty WString.  That element is the device PAOM string (for example
        /// "1;6ES7 215-1BG40-0XB0 ;V4.2"); real PLCs reject the session-setup echo
        /// if it is written back verbatim, and TIA Portal blanks it, while
        /// V1-initial S7-1200 firmware drops the connection without the element.
        /// </summary>
        public static byte[] StripPaomStringInSessionVersion(byte[] structBytes)
        {
            var needle = new byte[] { 0x82, 0x3F, 0x00, 0x15 };
            int idx = IndexOf(structBytes, needle);
            if (idx < 0) return structBytes;

            int afterDtype = idx + needle.Length;
            uint length = Vlq.DecodeUInt32(structBytes, afterDtype, out int consumed);

            var o = new List<byte>(structBytes.Length);
            o.AddRange(Slice(structBytes, 0, afterDtype));
            o.Add(0x00);                                    // empty WString
            int tailStart = afterDtype + consumed + (int)length;
            o.AddRange(Slice(structBytes, tailStart, structBytes.Length - tailStart));
            return o.ToArray();
        }

        private static int IndexOf(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) return i;
            }
            return -1;
        }
    }
}
