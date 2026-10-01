using System.Collections.Generic;

namespace CsS7CommPlus.Backend
{
    /// <summary>
    /// An optional capability for a backend that can say which names a PLC knows
    /// without reading them.
    ///
    /// A caller could instead browse and match against the names
    /// <see cref="IV3Backend.Tags"/> returns, but that misses the alternative
    /// spellings a backend accepts — a process-area tag answers to both its plain
    /// TIA name and the area-qualified one — and it copies the whole symbol list
    /// to compare a handful of names against it.
    /// </summary>
    public interface IV3SymbolResolver
    {
        /// <summary>
        /// Return the names the PLC does not know, in the order they were given.
        /// An empty result means every name resolved.
        /// </summary>
        IList<string> Unresolved(IEnumerable<string> names);
    }
}
