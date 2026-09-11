from pathlib import Path
import re
import subprocess
root = Path.cwd()
log = Path('/tmp/txindex-evidence/workspace-format.log').read_text()
reported = {str(Path(p).relative_to(root)) for p in re.findall(r'^Diff in (.*):\d+:$', log, re.M)}
changed = set(subprocess.check_output(['git','diff','--cached','--name-only'], text=True).splitlines())
assert reported, 'Formatter failed without normal diff output: '+log
assert reported.isdisjoint(changed), 'Formatting failure in changed files: '+str(reported & changed)
message = 'Changed Rust files pass formatting. Pre-existing workspace formatting drift remains only in unchanged files:\n'+'\n'.join(sorted(reported))+'\n'
Path('/tmp/txindex-evidence/format-status.txt').write_text(message)
print(message)
