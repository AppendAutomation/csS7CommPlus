namespace CsS7CommPlus.Models
{
    /// <summary>
    /// A symbol discovered by Explore.  Direct port of the Python Tag.
    /// </summary>
    public class Tag
    {
        /// <summary>Symbolic name, e.g. "HBTimer" or "SPDL BLU Winder DB.driveKp".</summary>
        public string TagName { get; set; } = string.Empty;

        /// <summary>Parent block, e.g. "MArea" or "SPDL BLU Winder DB".</summary>
        public string ParentBlock { get; set; } = string.Empty;

        /// <summary>Human-readable data type (e.g. "REAL", "INT", "BOOL"), when known.</summary>
        public string DataType { get; set; } = string.Empty;

        /// <summary>Numeric object relation id / access area used for reads and writes.</summary>
        public uint? RelationId { get; set; }

        /// <summary>Local id within the object.</summary>
        public int? LID { get; set; }

        /// <summary>Byte.bit offset, if parsed.</summary>
        public double? Offset { get; set; }

        /// <summary>Create an empty tag.</summary>
        public Tag() { }

        /// <summary>Create a tag with a name and optional parent/type.</summary>
        public Tag(string tagName, string parent = "", string dataType = "")
        {
            TagName = tagName;
            ParentBlock = parent;
            DataType = dataType;
        }

        /// <summary>"Parent.Name" when a parent is set, otherwise the name.</summary>
        public override string ToString() =>
            string.IsNullOrEmpty(ParentBlock) ? TagName : ParentBlock + "." + TagName;
    }
}
