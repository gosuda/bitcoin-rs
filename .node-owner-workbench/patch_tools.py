"""Restore parser and visibility fixes verified in the earlier node workbench."""
from pathlib import Path
p = Path(__file__).with_name('refactor.py')
s = p.read_text()
s = s.replace('PARSER.parse(text.encode())', "PARSER.parse(re.sub(rb'(?<=&)raw\\b', b'r_w', text.encode()))")
s = s.replace("visibility = 'pub ' if any(re.search(r'(?m)^pub (?:fn|struct|enum|const|type)\\b', m) for m in buckets[child]) else ''", "visibility = 'pub ' if any(re.search(r'(?m)^pub (?:fn|struct|enum|const|type)\\b', m) for m in buckets[child]) else 'pub(crate) '")
s = s.replace('        links = []\n        identifiers', "        links = [('use super::' + mod + ';') for mod in sorted(local_mods) if group and mod not in {name_of(source, n) for n, raw in parsed if n.type == 'mod_item' and is_test(raw)}]\n        identifiers")
s = s.replace("        text = re.sub(r'(?<![\\w])' + re.escape(old)", "        if old not in text:\n            continue\n        text = re.sub(r'(?<![\\w])' + re.escape(old)")
s = s.replace("        text = path.read_text()\n        if path.suffix == '.rs':", "        text = path.read_text()\n        if not any(k.split('::')[-1] in text for k in MIGRATIONS):\n            continue\n        if path.suffix == '.rs':")
s = s.replace("    return bool(re.search(r'#\\[cfg\\(test\\)\\]', raw))", "    for node in parse(raw).named_children:\n        if node.type == 'attribute_item' and re.search(r'#\\[cfg\\((?:test\\)|all\\(test\\b)', txt(raw, node)):\n            return True\n        if node.type not in ('line_comment', 'block_comment', 'attribute_item', 'inner_attribute_item'):\n            return False\n    return False")
s = s.replace("                add_map(old_owner + '::' + name, owner + '::' + group + '::' + name)", "                add_map(old_owner + '::' + name, owner + '::' + group + '::' + name)\n                if old_owner != owner:\n                    add_map(owner + '::' + name, owner + '::' + group + '::' + name)")
s = s.replace("        body = body.replace('use super::*;', '')\n        write(ROOT / new / (name + '.rs'), imports + '\\n' + '\\n'.join(links) + '\\n' + body)", "        body = body.replace('use super::*;', '')\n        body = re.sub(r'\\bsuper::', 'crate::' + owner + '::', body)\n        write(ROOT / new / (name + '.rs'), dedup_imports(imports + '\\n' + '\\n'.join(links) + '\\n' + body))")
s = s.replace("        if is_test(raw):\n            group = 'fixtures'", "        if is_test(raw) and name not in groups:\n            group = 'fixtures'")
s = s.replace("        prefix = raw[:raw.index('use ')]", "        prefix = raw[:raw.index('use ')]\n        prefix = prefix.replace('#[allow(unused_imports)]', '')")
s = s.replace("    all_groups = sorted(k for k in buckets if k)", "    buckets.setdefault('', [])\n    all_groups = sorted(k for k in buckets if k)")
s = s.replace("content = '\\n'.join(widen(m, root_scope=(group == '')) for m in members)", "content = '\\n'.join(widen(relative_paths(m, old_owner, force=True) if group else m, root_scope=(group == '')) for m in members)")
s = s.replace("        if path.suffix == '.rs':\n            changes = []", "        if path.suffix == '.rs':\n            if path.is_relative_to(ROOT):\n                module = '::'.join(path.relative_to(ROOT).with_suffix('').parts)\n                text = relative_paths(text, '' if module == 'lib' else module)\n            changes = []")
s = s.replace("    imports = canonical_imports(source, owner, local_mods)\n    buckets", """    imports = canonical_imports(source, owner, local_mods)
    for import_node, _ in items(imports):
        if import_node.type != 'use_declaration': continue
        for path, alias in use_leaves(imports, import_node):
            symbol = alias or path.split('::')[-1]
            if symbol in ('*', '_'): continue
            for prefix in ('crate::', 'bitcoin_rs_node::'):
                destination = prefix + path[7:] if prefix == 'bitcoin_rs_node::' and path.startswith('crate::') else path
                MIGRATIONS[prefix + old_owner + '::' + symbol] = destination
                MIGRATIONS[prefix + owner + '::' + symbol] = destination
    buckets""")
p.with_name('refactor_patched.py').write_text(s)
