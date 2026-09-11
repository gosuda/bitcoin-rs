from pathlib import Path
import sys
root=Path(sys.argv[1]).resolve()
def edit(path, old, new):
 p=root/path
 s=p.read_text()
 assert old in s,(path,old)
 p.write_text(s.replace(old,new))
edit('crates/index/README.md','rows to an exact active-chain prefix. `ScriptLive` is the compact reverse view', 'rows to an exact active-chain prefix.\n\n`ScriptLive` is the compact reverse view')
edit('crates/index/src/query.rs','//! One snapshot gate for transaction, history, and live-view queries.\n//! Resolution', '//! One snapshot gate for transaction, history, and live-view queries.\n//!\n//! Resolution')
edit('crates/index/src/query.rs','    /// Watermark progress of `required` capabilities against one applied\n    /// tip: `synced` when every one names that tip, `processed_height` the', '    /// Watermark progress of `required` capabilities against one applied tip.\n    ///\n    /// `synced` when every one names that tip, `processed_height` the')
