using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using CsS7CommPlus.V3.Protocol;

namespace CsS7CommPlus.V3.Symbols
{
    /// <summary>
    /// A browsed symbol: its name, the address the PLC reads it by, and the type
    /// metadata needed to decode and encode its value.
    /// </summary>
    public class SymbolicTag
    {
        /// <summary>The full symbolic name, exactly as TIA Portal spells it.</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>The access area: a DB area id, or a process-area RID.</summary>
        public uint AccessArea { get; set; }
        /// <summary>The LID path through the symbol tree.</summary>
        public IReadOnlyList<uint> Lids { get; set; } = new uint[0];
        /// <summary>The PLC's software datatype for this symbol.</summary>
        public SoftDataType SoftDataType { get; set; }
        /// <summary>The wire datatype used to encode a write, when one is known.</summary>
        public DataType? DataType { get; set; }
        /// <summary>The symbol's layout CRC; 0 skips the PLC's layout check.</summary>
        public uint SymbolCrc { get; set; }
        /// <summary>Array dimensions on the path to this symbol.</summary>
        public IReadOnlyList<ArrayDimension> ArrayDimensions { get; set; } = new ArrayDimension[0];
        /// <summary>Declared length of a string symbol.</summary>
        public int StringLength { get; set; }
        /// <summary>Byte address in an optimized block.</summary>
        public long OptAddress { get; set; }
        /// <summary>Bit offset in an optimized block.</summary>
        public int OptBitOffset { get; set; }
        /// <summary>Byte address in a standard block.</summary>
        public long NonOptAddress { get; set; }
        /// <summary>Bit offset in a standard block.</summary>
        public int NonOptBitOffset { get; set; }

        /// <summary>
        /// The access sub-area to request this symbol with: a data block's
        /// actual-value area, or the controller-area actual-value area for I/Q/M.
        /// </summary>
        public uint AccessSubArea =>
            AccessArea >= Ids.DbAccessAreaBase ? Ids.DbValueActual : Ids.ControllerAreaValueActual;

        /// <summary>Build a symbol from one flattened browse result.</summary>
        public static SymbolicTag FromVarInfo(VarInfo info)
        {
            var parts = info.AccessSequence.Split('.');
            if (parts.Length < 2)
                throw new S7ProtocolException($"Tag '{info.Name}' has an invalid access sequence '{info.AccessSequence}'");

            uint accessArea;
            var lids = new List<uint>(parts.Length - 1);
            try
            {
                accessArea = uint.Parse(parts[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                for (int i = 1; i < parts.Length; i++)
                    lids.Add(uint.Parse(parts[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture));
            }
            catch (Exception e) when (e is FormatException || e is OverflowException)
            {
                throw new S7ProtocolException(
                    $"Tag '{info.Name}' has an invalid access sequence '{info.AccessSequence}'");
            }

            var softType = (SoftDataType)info.SoftDataType;
            return new SymbolicTag
            {
                Name = info.Name,
                AccessArea = accessArea,
                Lids = lids,
                SoftDataType = softType,
                DataType = WireTypes.TryGetValue(softType, out var wire) ? wire : (DataType?)null,
                SymbolCrc = info.SymbolCrc,
                ArrayDimensions = info.ArrayDimensions,
                StringLength = info.StringLength,
                OptAddress = info.OptAddress,
                OptBitOffset = info.OptBitOffset,
                NonOptAddress = info.NonOptAddress,
                NonOptBitOffset = info.NonOptBitOffset,
            };
        }

        /// <summary>
        /// The wire datatype each software datatype is written as.  Ported from
        /// the MIT-licensed s7commplus Python backend (catalog.py).
        /// </summary>
        public static readonly Dictionary<SoftDataType, DataType> WireTypes = new Dictionary<SoftDataType, DataType>
        {
            { SoftDataType.Bool,        Protocol.DataType.Bool },
            { SoftDataType.BBool,       Protocol.DataType.Bool },
            { SoftDataType.Byte,        Protocol.DataType.Byte },
            { SoftDataType.Char,        Protocol.DataType.Byte },
            { SoftDataType.Word,        Protocol.DataType.Word },
            { SoftDataType.Int,         Protocol.DataType.Int },
            { SoftDataType.DWord,       Protocol.DataType.DWord },
            { SoftDataType.DInt,        Protocol.DataType.DInt },
            { SoftDataType.Real,        Protocol.DataType.Real },
            { SoftDataType.Date,        Protocol.DataType.UInt },
            { SoftDataType.TimeOfDay,   Protocol.DataType.UDInt },
            { SoftDataType.Time,        Protocol.DataType.DInt },
            { SoftDataType.S5Time,      Protocol.DataType.Word },
            { SoftDataType.DateAndTime, Protocol.DataType.Timestamp },
            { SoftDataType.String,      Protocol.DataType.S7String },
            { SoftDataType.LReal,       Protocol.DataType.LReal },
            { SoftDataType.ULInt,       Protocol.DataType.ULInt },
            { SoftDataType.LInt,        Protocol.DataType.LInt },
            { SoftDataType.LWord,       Protocol.DataType.LWord },
            { SoftDataType.USInt,       Protocol.DataType.USInt },
            { SoftDataType.UInt,        Protocol.DataType.UInt },
            { SoftDataType.UDInt,       Protocol.DataType.UDInt },
            { SoftDataType.SInt,        Protocol.DataType.SInt },
            { SoftDataType.WChar,       Protocol.DataType.UInt },
            { SoftDataType.WString,     Protocol.DataType.WString },
            { SoftDataType.LTime,       Protocol.DataType.Timespan },
            { SoftDataType.LTod,        Protocol.DataType.ULInt },
            { SoftDataType.Ldt,         Protocol.DataType.Timestamp },
        };

        /// <inheritdoc/>
        public override string ToString() => $"{Name} ({SoftDataType})";
    }

    /// <summary>
    /// A name-indexed snapshot of the PLC's browse metadata.  Names are matched
    /// exactly, as TIA Portal symbol names are case-sensitive.
    /// </summary>
    public class SymbolCatalog : IEnumerable<SymbolicTag>
    {
        private readonly Dictionary<string, SymbolicTag> _tags;

        /// <summary>Build a catalog from browsed symbols, keeping the first of any duplicate name.</summary>
        public SymbolCatalog(IEnumerable<SymbolicTag> tags)
        {
            _tags = new Dictionary<string, SymbolicTag>(StringComparer.Ordinal);
            foreach (var tag in tags)
            {
                if (!_tags.ContainsKey(tag.Name)) _tags[tag.Name] = tag;
            }
        }

        /// <summary>Number of symbols in the catalog.</summary>
        public int Count => _tags.Count;

        /// <summary>Resolve a symbolic name, or throw when the PLC does not know it.</summary>
        public SymbolicTag Resolve(string name)
        {
            if (_tags.TryGetValue(name, out var tag)) return tag;
            throw new KeyNotFoundException($"Unknown symbolic tag: '{name}'");
        }

        /// <summary>Resolve a symbolic name, returning false when the PLC does not know it.</summary>
        public bool TryResolve(string name, out SymbolicTag tag) => _tags.TryGetValue(name, out tag!);

        /// <inheritdoc/>
        public IEnumerator<SymbolicTag> GetEnumerator() => _tags.Values.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
