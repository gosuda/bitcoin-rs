"""Local scratch-helper corrections; no product files are changed here."""
from pathlib import Path
p = Path('.github/node-splits/split_core.py')
s = p.read_text()
a = '    tree = PARSER.parse(data)\n'
b = "    parser_data = re.sub(rb'&raw\\b(?!\\s*(?:const|mut)\\b)', b'&rAw', data)\n    tree = PARSER.parse(parser_data)\n"
assert s.count(a) == 1
s = s.replace(a,b)
a = "        links = b''\n        for name, definition in definitions.items():"
b = "        links = b''\n        for original_module in original:\n            if original_module.kind == 'mod_item' and original_module.name.encode() in used:\n                links += original_module.cfg + ('use super::' + original_module.name + ';\\n').encode()\n        for name, definition in definitions.items():"
assert s.count(a) == 1
s = s.replace(a,b)
p.write_text(s)
p = Path('.github/node-splits/validate.py')
s = p.read_text()
a = "    run(['git','worktree','add','--detach',str(work),BASE],cwd=checkout)"
b = "    run(['git','fetch','--quiet','--no-tags','--depth=1','origin',BASE],cwd=checkout)\n" + a
assert s.count(a) == 1
p.write_text(s.replace(a,b))
