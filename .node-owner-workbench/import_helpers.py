"""Import normalization for the requested one-shot node refactor."""
import refactor_patched as r


def dedup_imports(source):
    seen, edits = set(), []
    for node, raw in reversed(r.items(source)):
        if node.type != 'use_declaration':
            continue
        keep = []
        for path, alias in r.use_leaves(source, node):
            local = alias or path.split('::')[-1]
            if local in ('*', '_') or local not in seen:
                keep.append('use ' + path + ((' as ' + alias) if alias else '') + ';')
                if local not in ('*', '_'):
                    seen.add(local)
        start = node.start_byte
        if not keep:
            previous = node.prev_named_sibling
            while previous and previous.type == 'attribute_item':
                start = previous.start_byte
                previous = previous.prev_named_sibling
        edits.append((start, node.end_byte, '\n'.join(keep)))
    data = source.encode()
    for start, end, value in sorted(edits, reverse=True):
        data = data[:start] + value.encode() + data[end:]
    return data.decode()


def relative_paths(source, module, force=False):
    edits = []

    def resolve(path, parts):
        segments = path.split('::')
        if segments[0] not in ('self', 'super'):
            return path
        parts = list(parts)
        if segments[0] == 'self':
            segments.pop(0)
        while segments and segments[0] == 'super':
            if not parts:
                raise RuntimeError('super above crate: ' + path)
            parts.pop()
            segments.pop(0)
        return 'crate::' + '::'.join(parts + segments)

    def transform(path, parts):
        absolute = resolve(path, parts)
        migrated = r.replace_paths(absolute, r.MIGRATIONS)
        return migrated if force or migrated != absolute else path

    def visit(node, parts):
        if node.type == 'use_declaration':
            leaves = r.use_leaves(source, node)
            changed = [(transform(p, parts), a) for p, a in leaves]
            if changed != leaves:
                visibility = next((r.txt(source, c) + ' ' for c in node.children if c.type == 'visibility_modifier'), '')
                value = '\n'.join(visibility + 'use ' + p + ((' as ' + a) if a else '') + ';' for p, a in changed)
                edits.append((node.start_byte, node.end_byte, value))
            return
        if node.type in ('scoped_identifier', 'scoped_type_identifier'):
            value = r.txt(source, node)
            new = transform(value, parts)
            if new != value:
                edits.append((node.start_byte, node.end_byte, new))
                return
        if node.type == 'mod_item' and node.child_by_field_name('body') is not None:
            visit(node.child_by_field_name('body'), parts + [r.name_of(source, node)])
            return
        for child in node.named_children:
            visit(child, parts)

    visit(r.parse(source), module.split('::') if module else [])
    data = source.encode()
    for start, end, value in sorted(edits, reverse=True):
        data = data[:start] + value.encode() + data[end:]
    return data.decode()


r.dedup_imports = dedup_imports
r.relative_paths = relative_paths
