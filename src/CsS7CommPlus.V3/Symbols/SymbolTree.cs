using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using CsS7CommPlus.V3.Protocol;

namespace CsS7CommPlus.V3.Symbols
{
    /// <summary>What a symbol-tree node represents.</summary>
    public enum NodeType
    {
        /// <summary>Not classified.</summary>
        Undefined = 0,
        /// <summary>A data block or a process area: the root of one subtree.</summary>
        Root = 1,
        /// <summary>A plain member.</summary>
        Var = 2,
        /// <summary>One element of an array of a simple type.</summary>
        Array = 3,
        /// <summary>One element of an array of structs.</summary>
        StructArray = 4,
    }

    /// <summary>One node of the reconstructed symbol tree.</summary>
    public class SymbolNode
    {
        /// <summary>What this node represents.</summary>
        public NodeType NodeType { get; set; } = NodeType.Undefined;
        /// <summary>The node's own name fragment.</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>The access id this node contributes to the address path.</summary>
        public uint AccessId { get; set; }
        /// <summary>The node's software datatype.</summary>
        public int SoftDataType { get; set; }
        /// <summary>Relation id of the type object describing this node.</summary>
        public uint RelationId { get; set; }
        /// <summary>The vartype entry this node was built from.</summary>
        public TypeInfo.VartypeListElement? Vte { get; set; }
        /// <summary>Byte offset of this array element in an optimized block.</summary>
        public long ArrayAddrOffsetOpt { get; set; }
        /// <summary>Byte offset of this array element in a standard block.</summary>
        public long ArrayAddrOffsetNonOpt { get; set; }
        /// <summary>Child nodes.</summary>
        public List<SymbolNode> Children { get; } = new List<SymbolNode>();
    }

    /// <summary>One PLC array dimension.</summary>
    public class ArrayDimension
    {
        /// <summary>Lowest index.</summary>
        public int LowerBound { get; }
        /// <summary>Number of elements.</summary>
        public uint ElementCount { get; }

        /// <summary>Create a dimension.</summary>
        public ArrayDimension(int lowerBound, uint elementCount)
        {
            LowerBound = lowerBound;
            ElementCount = elementCount;
        }
    }

    /// <summary>A flattened, readable tag produced by the browse.</summary>
    public class VarInfo
    {
        /// <summary>The full symbolic name, for example "HMI_Tags.Core_Size".</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>
        /// The dot-separated hex address path: the access area, then the LIDs.
        /// </summary>
        public string AccessSequence { get; set; } = string.Empty;
        /// <summary>The tag's software datatype.</summary>
        public int SoftDataType { get; set; }
        /// <summary>Byte address in an optimized block.</summary>
        public long OptAddress { get; set; }
        /// <summary>Bit offset in an optimized block.</summary>
        public int OptBitOffset { get; set; }
        /// <summary>Byte address in a standard block.</summary>
        public long NonOptAddress { get; set; }
        /// <summary>Bit offset in a standard block.</summary>
        public int NonOptBitOffset { get; set; }
        /// <summary>The tag's layout CRC.</summary>
        public uint SymbolCrc { get; set; }
        /// <summary>Array dimensions on the path to this tag, outermost first.</summary>
        public IReadOnlyList<ArrayDimension> ArrayDimensions { get; set; } = new ArrayDimension[0];
        /// <summary>Declared length for a string tag.</summary>
        public int StringLength { get; set; }
    }

    /// <summary>
    /// Rebuilds the PLC's symbol tree from the browsed type objects and flattens
    /// it into readable tags.
    ///
    /// Ported from the MIT-licensed s7commplus Python backend (typeinfo.py).
    /// </summary>
    public static class SymbolTree
    {
        /// <summary>Expand each root node against its matching type object, in place.</summary>
        public static void BuildTree(List<SymbolNode> rootNodes, List<TypeInfo.PObject> typeObjects)
        {
            foreach (var node in rootNodes)
            {
                if (node.NodeType != NodeType.Root) continue;
                var obj = FindTypeObject(typeObjects, node.RelationId);
                if (obj != null) AddSubNodes(node, obj, typeObjects);
            }
        }

        private static TypeInfo.PObject? FindTypeObject(List<TypeInfo.PObject> objects, uint relationId)
        {
            foreach (var obj in objects)
            {
                if (obj.RelationId == relationId) return obj;
            }
            return null;
        }

        private static void AddSubNodes(SymbolNode node, TypeInfo.PObject obj, List<TypeInfo.PObject> objects)
        {
            for (int i = 0; i < obj.VartypeList.Count; i++)
            {
                var vte = obj.VartypeList[i];
                string name = i < obj.VarnameList.Count ? obj.VarnameList[i] : string.Empty;

                var subnode = new SymbolNode
                {
                    NodeType = NodeType.Undefined,
                    Name = name,
                    AccessId = vte.Lid,
                    SoftDataType = vte.SoftDataType,
                    Vte = vte,
                };
                node.Children.Add(subnode);

                var oi = vte.OffsetInfo;

                if (oi.Is1Dim)
                {
                    for (uint elem = 0; elem < oi.ArrayElementCount; elem++)
                    {
                        string label = "[" + (elem + (long)oi.ArrayLowerBound).ToString(CultureInfo.InvariantCulture) + "]";

                        if (oi.HasRelation)
                        {
                            var structType = FindTypeObject(objects, oi.RelationId);
                            long stride = TypeInfo.TComSize(structType);
                            var arrNode = new SymbolNode
                            {
                                NodeType = NodeType.StructArray,
                                Name = label,
                                AccessId = elem,
                                SoftDataType = vte.SoftDataType,
                                RelationId = oi.RelationId,
                                Vte = vte,
                                ArrayAddrOffsetOpt = elem * stride,
                                ArrayAddrOffsetNonOpt = elem * stride,
                            };
                            subnode.Children.Add(arrNode);
                            if (structType != null) AddSubNodes(arrNode, structType, objects);
                        }
                        else
                        {
                            long stride = TypeInfo.DataTypeSize(vte.SoftDataType, oi.Unspecified1);
                            subnode.Children.Add(new SymbolNode
                            {
                                NodeType = NodeType.Array,
                                Name = label,
                                AccessId = elem,
                                SoftDataType = vte.SoftDataType,
                                Vte = vte,
                                ArrayAddrOffsetOpt = elem * stride,
                                ArrayAddrOffsetNonOpt = elem * stride,
                            });
                        }
                    }
                }
                else if (oi.IsMdim)
                {
                    AddMdimSubNodes(subnode, vte, oi, objects);
                }
                else if (oi.HasRelation)
                {
                    var structType = FindTypeObject(objects, oi.RelationId);
                    if (structType != null) AddSubNodes(subnode, structType, objects);
                }
                // else: a scalar leaf, with no children.
            }
        }

        private static void AddMdimSubNodes(SymbolNode subnode, TypeInfo.VartypeListElement vte,
                                            TypeInfo.OffsetInfo oi, List<TypeInfo.PObject> objects)
        {
            var counts = oi.MdimElementCount;
            var lowers = oi.MdimLowerBounds;

            int actDimensions = 0;
            foreach (var c in counts) if (c > 0) actDimensions++;

            var structType = oi.HasRelation ? FindTypeObject(objects, oi.RelationId) : null;
            long stride = oi.HasRelation
                ? TypeInfo.TComSize(structType)
                : TypeInfo.DataTypeSize(vte.SoftDataType, oi.Unspecified1);

            var xx = new uint[6];
            uint arrId = 0;

            for (uint n = 1; n <= oi.ArrayElementCount; n++)
            {
                var sb = new StringBuilder("[");
                for (int j = actDimensions - 1; j >= 0; j--)
                {
                    if (j != actDimensions - 1) sb.Append(',');
                    sb.Append((xx[j] + (long)lowers[j]).ToString(CultureInfo.InvariantCulture));
                }
                sb.Append(']');
                string label = sb.ToString();

                long elemOff = (n - 1) * stride;

                if (oi.HasRelation)
                {
                    var arrNode = new SymbolNode
                    {
                        NodeType = NodeType.StructArray,
                        Name = label,
                        AccessId = arrId,
                        SoftDataType = vte.SoftDataType,
                        RelationId = oi.RelationId,
                        Vte = vte,
                        ArrayAddrOffsetOpt = elemOff,
                        ArrayAddrOffsetNonOpt = elemOff,
                    };
                    subnode.Children.Add(arrNode);
                    if (structType != null) AddSubNodes(arrNode, structType, objects);
                }
                else
                {
                    subnode.Children.Add(new SymbolNode
                    {
                        NodeType = NodeType.Array,
                        Name = label,
                        AccessId = arrId,
                        SoftDataType = vte.SoftDataType,
                        Vte = vte,
                        ArrayAddrOffsetOpt = elemOff,
                        ArrayAddrOffsetNonOpt = elemOff,
                    });
                }

                // Step the odometer, axis 0 fastest.
                xx[0]++;
                if (vte.SoftDataType == (int)SoftDataType.BBool && xx[0] >= counts[0] && counts[0] % 8 != 0)
                    arrId += 8 - (xx[0] % 8);           // rows of bits pad up to a byte
                for (int dim = 0; dim < 5; dim++)
                {
                    if (xx[dim] >= counts[dim]) { xx[dim] = 0; xx[dim + 1]++; }
                }
                arrId++;
            }
        }

        /// <summary>Walk each populated root and produce the flat list of readable tags.</summary>
        public static List<VarInfo> BuildFlatList(List<SymbolNode> rootNodes)
        {
            var result = new List<VarInfo>();
            foreach (var root in rootNodes)
            {
                if (root.Children.Count == 0) continue;
                Walk(root, string.Empty, string.Empty, 0, 0, new List<ArrayDimension>(), result);
            }
            return result;
        }

        private static List<ArrayDimension> DimensionsOf(TypeInfo.VartypeListElement? vte)
        {
            var dims = new List<ArrayDimension>();
            if (vte == null) return dims;

            var oi = vte.OffsetInfo;
            if (oi.IsMdim)
            {
                for (int i = 0; i < 6; i++)
                {
                    if (oi.MdimElementCount[i] > 0)
                        dims.Add(new ArrayDimension(oi.MdimLowerBounds[i], oi.MdimElementCount[i]));
                }
            }
            else if (oi.Is1Dim)
            {
                dims.Add(new ArrayDimension(oi.ArrayLowerBound, oi.ArrayElementCount));
            }
            return dims;
        }

        private static void Walk(SymbolNode node, string names, string accessIds,
                                 long optOff, long nonOptOff,
                                 List<ArrayDimension> arrayDimensions, List<VarInfo> result)
        {
            // Accumulate this node's contribution to the name and the address path.
            switch (node.NodeType)
            {
                case NodeType.Root:
                    names += node.Name;
                    accessIds += node.AccessId.ToString("X", CultureInfo.InvariantCulture);
                    break;
                case NodeType.Array:
                    names += node.Name;                 // an index label, with no dot
                    accessIds += "." + node.AccessId.ToString("X", CultureInfo.InvariantCulture);
                    break;
                case NodeType.StructArray:
                    names += node.Name;
                    accessIds += "." + node.AccessId.ToString("X", CultureInfo.InvariantCulture) + ".1";
                    break;
                default:
                    names += "." + node.Name;
                    accessIds += "." + node.AccessId.ToString("X", CultureInfo.InvariantCulture);
                    break;
            }

            if (node.NodeType == NodeType.Array || node.NodeType == NodeType.StructArray)
            {
                var extended = new List<ArrayDimension>(arrayDimensions);
                extended.AddRange(DimensionsOf(node.Vte));
                arrayDimensions = extended;
            }

            if (node.Children.Count > 0)
            {
                // Descending into a branch advances the running byte offsets.
                if (node.NodeType == NodeType.Array && node.Vte != null)
                {
                    optOff = node.Vte.OffsetInfo.OptAddr;
                    nonOptOff = node.Vte.OffsetInfo.NonOptAddr;
                }
                else if (node.NodeType == NodeType.StructArray)
                {
                    optOff += node.ArrayAddrOffsetOpt;
                    nonOptOff += node.ArrayAddrOffsetNonOpt;
                }
                else if (node.Vte != null)
                {
                    optOff += node.Vte.OffsetInfo.OptAddr;
                    nonOptOff += node.Vte.OffsetInfo.NonOptAddr;
                }

                foreach (var child in node.Children)
                {
                    long childOpt = optOff, childNonOpt = nonOptOff;
                    if (child.NodeType == NodeType.Array)
                    {
                        childOpt += child.ArrayAddrOffsetOpt;
                        childNonOpt += child.ArrayAddrOffsetNonOpt;
                    }
                    Walk(child, names, accessIds, childOpt, childNonOpt, arrayDimensions, result);
                }
                return;
            }

            // A leaf: emit it when its datatype is a readable one.
            if (!TypeInfo.IsSupported(node.SoftDataType)) return;

            var vte = node.Vte;
            var info = new VarInfo
            {
                Name = names,
                AccessSequence = accessIds,
                SoftDataType = node.SoftDataType,
                SymbolCrc = vte?.SymbolCrc ?? 0,
                ArrayDimensions = arrayDimensions,
                StringLength = vte?.OffsetInfo.Unspecified1 ?? 0,
            };

            if (node.NodeType == NodeType.Array)
            {
                // A basic-array element: the offset already includes the stride.
                info.OptAddress = optOff;
                info.NonOptAddress = nonOptOff;
            }
            else if (vte != null)
            {
                info.OptAddress = optOff + vte.OffsetInfo.OptAddr;
                info.NonOptAddress = nonOptOff + vte.OffsetInfo.NonOptAddr;
            }

            if (node.SoftDataType == (int)SoftDataType.Bool && vte != null)
            {
                info.OptBitOffset = vte.AttributeBitOffset;
                info.NonOptBitOffset = vte.Classic ? vte.NonOptBitOffset : vte.AttributeBitOffset;
            }
            else if (node.SoftDataType == (int)SoftDataType.BBool && vte != null)
            {
                info.OptBitOffset = vte.OptBitOffset;
            }

            result.Add(info);
        }
    }
}
