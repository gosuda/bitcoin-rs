pub(crate) fn walk(root: &std::path::Path, extensions: &[&str]) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    visit(root, extensions, &mut files);
    files.sort();
    files
}

fn visit(dir: &std::path::Path, extensions: &[&str], files: &mut Vec<std::path::PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = read.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || name == "target" {
                continue;
            }
            visit(&path, extensions, files);
        } else if kind.is_file() {
            if let Some(extension) = path.extension().and_then(|value| value.to_str()) {
                if extensions.contains(&extension) {
                    files.push(path);
                }
            }
        }
    }
}

pub(crate) fn relative(root: &std::path::Path, file: &std::path::Path) -> String {
    let relative = file.strip_prefix(root).unwrap_or(file);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn prose_lines(text: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    let mut fence: Option<bool> = None;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            match fence {
                None => {
                    fence = Some(trimmed.starts_with("```"));
                    continue;
                }
                Some(backticks) => {
                    if backticks == trimmed.starts_with("```") {
                        fence = None;
                    }
                }
            }
            continue;
        }
        if fence.is_none() {
            lines.push((index + 1, line));
        }
    }
    lines
}

fn code_span_ranges(line: &str) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'`' {
            index += 1;
            continue;
        }
        let opening = index;
        while index < bytes.len() && bytes[index] == b'`' {
            index += 1;
        }
        let run = index - opening;
        let content_start = index;
        let mut closing = index;
        let mut found = None;
        while closing < bytes.len() {
            if bytes[closing] == b'`' {
                let start = closing;
                while closing < bytes.len() && bytes[closing] == b'`' {
                    closing += 1;
                }
                if closing - start == run {
                    found = Some((start, closing));
                    break;
                }
            } else {
                closing += 1;
            }
        }
        if let Some((close_start, close_end)) = found {
            ranges.push((content_start, close_start));
            index = close_end;
        }
    }
    ranges
}

pub(crate) fn code_spans(line: &str) -> Vec<&str> {
    code_span_ranges(line)
        .into_iter()
        .map(|(start, end)| &line[start..end])
        .collect()
}

pub(crate) fn strip_code_spans(line: &str) -> String {
    let mut bytes = line.as_bytes().to_vec();
    for (start, end) in code_span_ranges(line) {
        bytes[start..end].fill(b' ');
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{code_spans, prose_lines, strip_code_spans};

    #[test]
    fn code_spans_handles_single_and_double_backticks() {
        let line = "a `one` b ``two ` three`` c";
        assert_eq!(code_spans(line), vec!["one", "two ` three"]);
    }

    #[test]
    fn prose_lines_drops_fenced_blocks() {
        let text = "one\n```\ntwo\n```\nthree\n~~~\nfour\n~~~\nfive\n";
        let lines: Vec<_> = prose_lines(text)
            .into_iter()
            .map(|(_, line)| line)
            .collect();
        assert_eq!(lines, vec!["one", "three", "five"]);
    }

    #[test]
    fn strip_code_spans_hides_span_contents() {
        assert_eq!(strip_code_spans("see `[a](b)` here"), "see `      ` here");
    }
}
