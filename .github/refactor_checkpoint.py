from pathlib import Path
import re
p=Path('crates/node/src/checkpoint.rs'); orig=p.read_text(); lines=orig.splitlines(True)
def sl(a,b): return ''.join(lines[a-1:b])
def write(rel,body):
 q=p.parent/rel; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(body.rstrip()+'\n')
def localize_fns(body):
 return re.sub(r'(?m)^fn ', 'pub(super) fn ', body)

header=sl(23,29)+sl(56,430)
header=localize_fns(header)
header=header.replace('\nconst ', '\npub(super) const ').lstrip().replace('const ', 'pub(super) const ', 1) if header.startswith('const ') else header.replace('\nconst ', '\npub(super) const ')
write('checkpoint/headers.rs','//! Canonical header-checkpoint codec and commitments.\n\nuse super::*;\n\n'+header)
io=localize_fns(sl(1064,1215))
write('checkpoint/io.rs','//! Durable checkpoint file publication primitives and failpoints.\n\nuse super::*;\n\n'+io)
load=localize_fns(sl(1216,1601))
write('checkpoint/load.rs','//! Manifest validation, artifact loading, and generation discovery.\n\nuse super::*;\n\n'+load)
house=localize_fns(sl(1602,1652))
write('checkpoint/housekeeping.rs','//! Best-effort cleanup of superseded checkpoint generations.\n\nuse super::*;\n\n'+house)
codec=localize_fns(sl(1653,1728))
write('checkpoint/codec.rs','//! Small manifest text and hex conversion helpers.\n\nuse super::*;\n\n'+codec)
write('checkpoint/tests.rs','use super::*;\nuse super::headers::*;\nuse super::io::*;\nuse super::load::*;\n\n'+sl(1731,len(lines)-1))
root=sl(1,22)+sl(30,55)+'''\nmod codec;\nmod headers;\nmod housekeeping;\nmod io;\nmod load;\n#[cfg(test)]\nmod tests;\n\npub(crate) use headers::{HeaderCheckpointConfig, HeaderCheckpointError, HeaderCheckpointMetadata, HeaderCheckpointPoint, HeaderCheckpointTip, HeaderCheckpointWrite, RestoredHeaders, read_headers, write_headers};\nuse headers::write_selected_headers;\nuse codec::*;\nuse housekeeping::*;\nuse io::*;\nuse load::*;\n\n'''+sl(432,1063)
p.write_text(root.rstrip()+'\n')
