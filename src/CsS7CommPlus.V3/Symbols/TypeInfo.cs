using System;
using System.Collections.Generic;
using System.Text;
using CsS7CommPlus.V3.Protocol;

namespace CsS7CommPlus.V3.Symbols
{
    /// <summary>
    /// Decoding of the type-information container an S7-1200/1500 returns from an
    /// Explore request: the vartype lists, name lists and object tree that
    /// together describe every symbol's address and type.
    ///
    /// Ported from the MIT-licensed s7commplus Python backend (typeinfo.py).
    /// </summary>
    public static class TypeInfo
    {
        /// <summary>Attribute 1502, a struct or UDT's byte size, stored big-endian.</summary>
        public const uint TiTComSize = 1502;

        /// <summary>
        /// Leaf datatypes that browsing emits as readable tags.  Containers and
        /// markers — void, array, struct, end-of-struct, multi-instance FB,
        /// variant, DTL and the system ids — are not leaves; their members are
        /// emitted instead.
        /// </summary>
        public static readonly HashSet<SoftDataType> SupportedSoftDataTypes = new HashSet<SoftDataType>
        {
            SoftDataType.Bool, SoftDataType.Byte, SoftDataType.Char, SoftDataType.Word,
            SoftDataType.Int, SoftDataType.DWord, SoftDataType.DInt, SoftDataType.Real,
            SoftDataType.Date, SoftDataType.TimeOfDay, SoftDataType.Time, SoftDataType.S5Time,
            SoftDataType.DateAndTime, SoftDataType.String, SoftDataType.Pointer, SoftDataType.Any,
            SoftDataType.BBool, SoftDataType.LReal, SoftDataType.ULInt, SoftDataType.LInt,
            SoftDataType.LWord, SoftDataType.USInt, SoftDataType.UInt, SoftDataType.UDInt,
            SoftDataType.SInt, SoftDataType.WChar, SoftDataType.WString, SoftDataType.LTime,
            SoftDataType.LTod, SoftDataType.Ldt,
        };

        /// <summary>Whether this datatype is a leaf that browsing emits as a readable tag.</summary>
        public static bool IsSupported(int code) => SupportedSoftDataTypes.Contains((SoftDataType)code);

        private static readonly HashSet<SoftDataType> Size1 = new HashSet<SoftDataType>
        {
            SoftDataType.Bool, SoftDataType.Byte, SoftDataType.Char,
            SoftDataType.USInt, SoftDataType.SInt, SoftDataType.BBool,
        };

        private static readonly HashSet<SoftDataType> Size2 = new HashSet<SoftDataType>
        {
            SoftDataType.Word, SoftDataType.Int, SoftDataType.UInt,
            SoftDataType.Date, SoftDataType.S5Time, SoftDataType.WChar,
        };

        private static readonly HashSet<SoftDataType> Size4 = new HashSet<SoftDataType>
        {
            SoftDataType.DWord, SoftDataType.DInt, SoftDataType.Real,
            SoftDataType.TimeOfDay, SoftDataType.Time, SoftDataType.UDInt,
        };

        private static readonly HashSet<SoftDataType> Size8 = new HashSet<SoftDataType>
        {
            SoftDataType.LReal, SoftDataType.ULInt, SoftDataType.LInt, SoftDataType.LWord,
            SoftDataType.DateAndTime, SoftDataType.LTime, SoftDataType.LTod, SoftDataType.Ldt,
        };

        /// <summary>
        /// Element byte stride for a software datatype.  <paramref name="stringLength"/>
        /// is the array offset-info's first unspecified field and applies only to
        /// STRING and WSTRING, whose stride is that length plus two.
        /// </summary>
        public static int DataTypeSize(int code, int stringLength = 0)
        {
            var t = (SoftDataType)code;
            if (Size1.Contains(t)) return 1;
            if (Size2.Contains(t)) return 2;
            if (Size4.Contains(t)) return 4;
            if (Size8.Contains(t)) return 8;
            if (t == SoftDataType.Dtl) return 12;
            if (t == SoftDataType.Pointer) return 6;
            if (t == SoftDataType.Any || t == SoftDataType.Remote) return 10;
            if (t == SoftDataType.String || t == SoftDataType.WString) return stringLength + 2;
            return 0;
        }

        // --- POffsetInfoType -----------------------------------------------

        /// <summary>
        /// The address and dimension information attached to one vartype element.
        /// Which fields are populated depends on the 4-bit selector held in the
        /// element's attribute flags.
        /// </summary>
        public class OffsetInfo
        {
            /// <summary>The POffsetInfoType selector, 0 to 15.</summary>
            public int Code { get; set; }
            /// <summary>Byte address in an optimized block.</summary>
            public uint OptAddr { get; set; }
            /// <summary>Byte address in a standard (non-optimized) block.</summary>
            public uint NonOptAddr { get; set; }
            /// <summary>First unspecified field; the declared length for strings.</summary>
            public ushort Unspecified1 { get; set; }
            /// <summary>Second unspecified field.</summary>
            public ushort Unspecified2 { get; set; }
            /// <summary>Lowest index of a one-dimensional array.</summary>
            public int ArrayLowerBound { get; set; }
            /// <summary>Total element count of the array.</summary>
            public uint ArrayElementCount { get; set; }
            /// <summary>Lowest index per axis of a multi-dimensional array.</summary>
            public int[] MdimLowerBounds { get; set; } = new int[6];
            /// <summary>Element count per axis of a multi-dimensional array.</summary>
            public uint[] MdimElementCount { get; set; } = new uint[6];
            /// <summary>Struct size in a standard block.</summary>
            public uint NonOptStructSize { get; set; }
            /// <summary>Struct size in an optimized block.</summary>
            public uint OptStructSize { get; set; }
            /// <summary>Relation id of the member's own type object.</summary>
            public uint RelationId { get; set; }
            /// <summary>Whether this member is a one-dimensional array.</summary>
            public bool Is1Dim { get; set; }
            /// <summary>Whether this member is a multi-dimensional array.</summary>
            public bool IsMdim { get; set; }
            /// <summary>Whether this member refers to a further type object.</summary>
            public bool HasRelation { get; set; }
        }

        /// <summary>
        /// Parse the POffsetInfoType variant selected by
        /// <paramref name="offsetInfoType"/>.  Its fields are little-endian, unlike
        /// the rest of the protocol.
        /// </summary>
        public static OffsetInfo ParseOffsetInfo(byte[] data, int offset, int offsetInfoType, out int newOffset)
        {
            var oi = new OffsetInfo { Code = offsetInfoType };

            switch (offsetInfoType)
            {
                case 1:
                case 8:          // Std
                    {
                        ushort a = ReadUInt16Le(data, offset);
                        ushort b = ReadUInt16Le(data, offset + 2);
                        if (offsetInfoType == 8) { oi.OptAddr = a; oi.NonOptAddr = b; }
                        else { oi.NonOptAddr = a; oi.OptAddr = b; }       // legacy order is swapped
                        newOffset = offset + 4;
                        return oi;
                    }

                case 2:
                case 9:          // String
                    {
                        oi.Unspecified1 = ReadUInt16Le(data, offset);
                        oi.Unspecified2 = ReadUInt16Le(data, offset + 2);
                        oi.OptAddr = ReadUInt32Le(data, offset + 4);
                        oi.NonOptAddr = ReadUInt32Le(data, offset + 8);
                        newOffset = offset + 12;
                        return oi;
                    }

                case 3:
                case 10:         // Array1Dim
                    {
                        ReadArrayHead(data, offset, oi);
                        oi.Is1Dim = true;
                        newOffset = offset + 20;
                        return oi;
                    }

                case 4:
                case 11:         // ArrayMDim
                    {
                        ReadArrayHead(data, offset, oi);
                        offset += 20;
                        offset = ReadMdim(data, offset, oi);
                        oi.IsMdim = true;
                        newOffset = offset;
                        return oi;
                    }

                case 5:
                case 12:         // Struct
                    {
                        oi.Unspecified1 = ReadUInt16Le(data, offset);
                        oi.Unspecified2 = ReadUInt16Le(data, offset + 2);
                        oi.OptAddr = ReadUInt32Le(data, offset + 4);
                        oi.NonOptAddr = ReadUInt32Le(data, offset + 8);
                        oi.RelationId = ReadUInt32Le(data, offset + 12);
                        oi.HasRelation = true;
                        newOffset = offset + 4 + 8 + 4 + 16;              // HHIII + 4I
                        return oi;
                    }

                case 6:
                case 13:         // Struct1Dim
                    {
                        ReadArrayHead(data, offset, oi);
                        oi.NonOptStructSize = ReadUInt32Le(data, offset + 20);
                        oi.OptStructSize = ReadUInt32Le(data, offset + 24);
                        oi.RelationId = ReadUInt32Le(data, offset + 28);
                        oi.HasRelation = true;
                        oi.Is1Dim = true;
                        newOffset = offset + 20 + 12 + 16;                // HHIIiI + III + 4I
                        return oi;
                    }

                case 7:
                case 14:         // StructMDim
                    {
                        ReadArrayHead(data, offset, oi);
                        offset += 20;
                        offset = ReadMdim(data, offset, oi);
                        oi.NonOptStructSize = ReadUInt32Le(data, offset);
                        oi.OptStructSize = ReadUInt32Le(data, offset + 4);
                        oi.RelationId = ReadUInt32Le(data, offset + 8);
                        offset += 12 + 16;                                // III + 4I
                        oi.HasRelation = true;
                        oi.IsMdim = true;
                        newOffset = offset;
                        return oi;
                    }

                case 15:         // FbSfb
                    {
                        oi.Unspecified1 = ReadUInt16Le(data, offset);
                        oi.Unspecified2 = ReadUInt16Le(data, offset + 2);
                        oi.OptAddr = ReadUInt32Le(data, offset + 4);
                        oi.NonOptAddr = ReadUInt32Le(data, offset + 8);
                        oi.RelationId = ReadUInt32Le(data, offset + 12);
                        oi.HasRelation = true;
                        newOffset = offset + 4 + 8 + 4 + 16 + 8;          // HHIII + 4I + II
                        return oi;
                    }

                case 0:          // FbArray
                    {
                        oi.Unspecified1 = ReadUInt16Le(data, offset);
                        oi.Unspecified2 = ReadUInt16Le(data, offset + 2);
                        oi.OptAddr = ReadUInt32Le(data, offset + 4);
                        oi.NonOptAddr = ReadUInt32Le(data, offset + 8);
                        offset += 12;
                        oi.RelationId = ReadUInt32Le(data, offset);       // relation info, then 4 reserved
                        offset += 20;
                        oi.ArrayElementCount = ReadUInt32Le(data, offset + 8);   // third section entry
                        offset += 24;
                        offset = ReadMdim(data, offset, oi);
                        oi.HasRelation = true;
                        newOffset = offset;
                        return oi;
                    }

                default:
                    throw new S7ProtocolException($"Unsupported offsetinfotype: {offsetInfoType}");
            }
        }

        private static void ReadArrayHead(byte[] data, int offset, OffsetInfo oi)
        {
            oi.Unspecified1 = ReadUInt16Le(data, offset);
            oi.Unspecified2 = ReadUInt16Le(data, offset + 2);
            oi.OptAddr = ReadUInt32Le(data, offset + 4);
            oi.NonOptAddr = ReadUInt32Le(data, offset + 8);
            oi.ArrayLowerBound = unchecked((int)ReadUInt32Le(data, offset + 12));
            oi.ArrayElementCount = ReadUInt32Le(data, offset + 16);
        }

        private static int ReadMdim(byte[] data, int offset, OffsetInfo oi)
        {
            var lowers = new int[6];
            for (int i = 0; i < 6; i++) lowers[i] = unchecked((int)ReadUInt32Le(data, offset + i * 4));
            offset += 24;

            var counts = new uint[6];
            for (int i = 0; i < 6; i++) counts[i] = ReadUInt32Le(data, offset + i * 4);
            offset += 24;

            oi.MdimLowerBounds = lowers;
            oi.MdimElementCount = counts;
            return offset;
        }

        private static ushort ReadUInt16Le(byte[] data, int offset)
        {
            if (offset + 2 > data.Length) throw new S7ProtocolException("Truncated type-info offset info");
            return (ushort)(data[offset] | (data[offset + 1] << 8));
        }

        private static uint ReadUInt32Le(byte[] data, int offset)
        {
            if (offset + 4 > data.Length) throw new S7ProtocolException("Truncated type-info offset info");
            return (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
        }

        // --- vartype list ---------------------------------------------------

        /// <summary>One entry of a vartype list: a single member's address and type.</summary>
        public class VartypeListElement
        {
            /// <summary>Local id addressing this member within its object.</summary>
            public uint Lid { get; set; }
            /// <summary>Layout CRC of the symbol; 0 skips the check on access.</summary>
            public uint SymbolCrc { get; set; }
            /// <summary>The member's software datatype.</summary>
            public int SoftDataType { get; set; }
            /// <summary>Attribute flags; bits 12 to 15 select the offset-info variant.</summary>
            public ushort AttributeFlags { get; set; }
            /// <summary>Bit-offset flags for bit-addressed members.</summary>
            public byte BitOffsetInfoFlags { get; set; }
            /// <summary>The member's address and dimension info.</summary>
            public OffsetInfo OffsetInfo { get; set; } = new OffsetInfo();

            /// <summary>The 4-bit offset-info selector from attribute-flag bits 12 to 15.</summary>
            public int OffsetInfoType => (AttributeFlags >> 12) & 0x0F;
            /// <summary>Optimized bit offset carried in the low three attribute-flag bits.</summary>
            public int AttributeBitOffset => AttributeFlags & 0x07;
            /// <summary>Bit offset in a standard block.</summary>
            public int NonOptBitOffset => (BitOffsetInfoFlags & 0x70) >> 4;
            /// <summary>Bit offset in an optimized block.</summary>
            public int OptBitOffset => BitOffsetInfoFlags & 0x07;
            /// <summary>Whether the member uses the classic (non-optimized) layout.</summary>
            public bool Classic => (BitOffsetInfoFlags & 0x08) != 0;
        }

        /// <summary>Parse one vartype element and its embedded offset info.</summary>
        public static VartypeListElement ParseVartypeElement(byte[] data, int offset, out int newOffset)
        {
            var el = new VartypeListElement
            {
                Lid = ReadUInt32Le(data, offset),
                SymbolCrc = ReadUInt32Le(data, offset + 4),
            };
            offset += 8;

            if (offset + 4 > data.Length) throw new S7ProtocolException("Truncated vartype element");
            el.SoftDataType = data[offset];
            offset += 1;
            el.AttributeFlags = S7Codec.ReadUInt16(data, offset);      // big-endian, unlike the rest
            offset += 2;
            el.BitOffsetInfoFlags = data[offset];
            offset += 1;

            el.OffsetInfo = ParseOffsetInfo(data, offset, el.OffsetInfoType, out offset);
            newOffset = offset;
            return el;
        }

        /// <summary>
        /// Parse a vartype list.  It is a run of blocks, each opening with a
        /// big-endian 16-bit length and ended by a zero-length block.  Only the
        /// first block carries a leading little-endian 32-bit starting index,
        /// counted inside that block's length.  A long member list is split
        /// across several blocks, so the loop is required: treating the list as
        /// one block plus a terminator misaligns the cursor and corrupts the
        /// name list that follows.
        /// </summary>
        public static List<VartypeListElement> ParseVartypeList(byte[] data, int offset, out int newOffset)
        {
            var elements = new List<VartypeListElement>();
            bool firstBlock = true;

            while (true)
            {
                if (offset + 2 > data.Length) throw new S7ProtocolException("Truncated vartype list");
                int blockLen = S7Codec.ReadUInt16(data, offset);
                offset += 2;
                if (blockLen == 0) break;

                int blockEnd = offset + blockLen;
                if (firstBlock) { offset += 4; firstBlock = false; }    // leading starting index

                while (offset < blockEnd)
                {
                    var el = ParseVartypeElement(data, offset, out offset);
                    elements.Add(el);
                }
            }

            newOffset = offset;
            return elements;
        }

        /// <summary>
        /// Parse a name list: blocks of length-prefixed, null-terminated names,
        /// ending at a zero-length block.
        /// </summary>
        public static List<string> ParseVarnameList(byte[] data, int offset, out int newOffset)
        {
            var names = new List<string>();

            while (true)
            {
                if (offset + 2 > data.Length) throw new S7ProtocolException("Truncated name list");
                int blockLen = S7Codec.ReadUInt16(data, offset);
                offset += 2;
                if (blockLen == 0) break;

                int end = offset + blockLen;
                while (offset < end)
                {
                    int nameLen = data[offset];
                    offset += 1;
                    names.Add(Encoding.UTF8.GetString(S7Codec.Slice(data, offset, nameLen)));
                    offset += nameLen;
                    offset += 1;                                        // trailing zero byte
                }
            }

            newOffset = offset;
            return names;
        }

        // --- object tree ----------------------------------------------------

        /// <summary>A node of the object tree: one type, container or nested object.</summary>
        public class PObject
        {
            /// <summary>The object's relation id.</summary>
            public uint RelationId { get; set; }
            /// <summary>The object's class id.</summary>
            public uint ClassId { get; set; }
            /// <summary>Attribute values by attribute id, as raw bytes.</summary>
            public Dictionary<uint, byte[]> Attributes { get; } = new Dictionary<uint, byte[]>();
            /// <summary>The object's member address and type entries.</summary>
            public List<VartypeListElement> VartypeList { get; set; } = new List<VartypeListElement>();
            /// <summary>The object's member names, positionally matching the vartype list.</summary>
            public List<string> VarnameList { get; set; } = new List<string>();
            /// <summary>Nested objects.</summary>
            public List<PObject> Objects { get; } = new List<PObject>();
        }

        /// <summary>Parse one object, from its start tag to its terminator.</summary>
        public static PObject ParseObject(byte[] data, int offset, out int newOffset)
        {
            if (data[offset] != (byte)ElementId.StartOfObject)
                throw new S7ProtocolException($"Expected an object start tag, got 0x{data[offset]:X2}");
            offset += 1;

            uint relationId = S7Codec.ReadUInt32(data, offset);
            offset += 4;
            uint classId = Vlq.DecodeUInt32(data, offset, out int c);
            offset += c;
            for (int i = 0; i < 2; i++)              // ClassFlags, AttributeId
            {
                Vlq.DecodeUInt32(data, offset, out int ci);
                offset += ci;
            }

            var obj = new PObject { RelationId = relationId, ClassId = classId };

            while (offset < data.Length)
            {
                byte tag = data[offset];

                if (tag == (byte)ElementId.TerminatingObject) { offset += 1; break; }

                if (tag == (byte)ElementId.Attribute)
                {
                    offset += 1;
                    uint attrId = Vlq.DecodeUInt32(data, offset, out int ca);
                    offset += ca;
                    var value = S7Codec.DecodePValueToBytes(data, offset, out int cv);
                    offset += cv;
                    obj.Attributes[attrId] = value;
                }
                else if (tag == (byte)ElementId.VarTypeList)
                {
                    offset += 1;
                    obj.VartypeList = ParseVartypeList(data, offset, out offset);
                }
                else if (tag == (byte)ElementId.VarNameList)
                {
                    offset += 1;
                    obj.VarnameList = ParseVarnameList(data, offset, out offset);
                }
                else if (tag == (byte)ElementId.StartOfObject)
                {
                    obj.Objects.Add(ParseObject(data, offset, out offset));
                }
                else
                {
                    offset += 1;                     // unknown tag: skip defensively
                }
            }

            newOffset = offset;
            return obj;
        }

        /// <summary>Parse a run of sibling objects.</summary>
        public static List<PObject> ParseObjectList(byte[] data, int offset, out int newOffset)
        {
            var objects = new List<PObject>();
            while (offset < data.Length && data[offset] == (byte)ElementId.StartOfObject)
                objects.Add(ParseObject(data, offset, out offset));
            newOffset = offset;
            return objects;
        }

        private static PObject? FindContainer(List<PObject> objects, uint classId)
        {
            foreach (var obj in objects)
            {
                if (obj.ClassId == classId) return obj;
                var found = FindContainer(obj.Objects, classId);
                if (found != null) return found;
            }
            return null;
        }

        /// <summary>
        /// Return the per-type objects from an Explore of the type-info container:
        /// skip the leading return value and any preamble, parse the object stream
        /// and return the container's children.
        /// </summary>
        public static List<PObject> ExtractTypeInfoObjects(byte[] response)
        {
            Vlq.DecodeUInt32(response, 0, out int offset);
            while (offset < response.Length && response[offset] != (byte)ElementId.StartOfObject) offset++;
            if (offset >= response.Length) return new List<PObject>();

            var objects = ParseObjectList(response, offset, out _);
            var container = FindContainer(objects, Ids.ClassOmsTypeInfoContainer);
            return container != null ? container.Objects : new List<PObject>();
        }

        /// <summary>Read attribute 1502, a type's byte size, from an object.</summary>
        public static uint TComSize(PObject? obj)
        {
            if (obj == null) return 0;
            if (!obj.Attributes.TryGetValue(TiTComSize, out var raw) || raw.Length == 0) return 0;
            if (raw.Length < 4)
            {
                uint partial = 0;
                foreach (var b in raw) partial = (partial << 8) | b;
                return partial;
            }
            return S7Codec.ReadUInt32(raw, 0);
        }
    }
}
