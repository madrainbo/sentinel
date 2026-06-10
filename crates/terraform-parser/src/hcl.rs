//! A small, dependency-free HCL parser — enough of HashiCorp Configuration
//! Language to extract blocks, labels, attributes, lists, objects, heredocs and
//! raw expressions for the Terraform security rules. Deterministic; never panics
//! (malformed input degrades gracefully). It is intentionally lenient: it parses
//! structure, not full HCL expression semantics.
//!
//! Nesting depth is capped at [`fact_model::limits::MAX_HCL_DEPTH`]: this is a
//! recursive-descent parser, so without the cap deeply nested blocks/values
//! would overflow the stack and abort the process (a DoS on untrusted input).
//! Past the cap we stop descending and degrade gracefully.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    List(Vec<Value>),
    Obj(Vec<(String, Value)>),
    /// Any other expression (number, bool, reference, function call) as raw text.
    Raw(String),
}

impl Value {
    /// Flatten a value to a searchable string (for substring rules over e.g.
    /// embedded IAM policy JSON).
    pub fn text(&self) -> String {
        match self {
            Value::Str(s) | Value::Raw(s) => s.clone(),
            Value::List(xs) => xs.iter().map(|v| v.text()).collect::<Vec<_>>().join(","),
            Value::Obj(a) => a
                .iter()
                .map(|(k, v)| format!("{k}={}", v.text()))
                .collect::<Vec<_>>()
                .join(","),
        }
    }

    /// True if this value (a string, or a list/obj containing one) equals `needle`.
    pub fn contains_scalar(&self, needle: &str) -> bool {
        match self {
            Value::Str(s) | Value::Raw(s) => s == needle,
            Value::List(xs) => xs.iter().any(|v| v.contains_scalar(needle)),
            Value::Obj(a) => a.iter().any(|(_, v)| v.contains_scalar(needle)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub typ: String,
    pub labels: Vec<String>,
    pub attrs: Vec<(String, Value)>,
    pub blocks: Vec<Block>,
    /// 1-based source line where the block begins.
    pub line: u32,
}

impl Block {
    pub fn attr(&self, name: &str) -> Option<&Value> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }
    pub fn child_blocks<'a>(&'a self, typ: &'a str) -> impl Iterator<Item = &'a Block> {
        self.blocks.iter().filter(move |b| b.typ == typ)
    }
    /// Recursively walk this block and all descendants.
    pub fn walk<'a>(&'a self, out: &mut Vec<&'a Block>) {
        out.push(self);
        for b in &self.blocks {
            b.walk(out);
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    src: &'a str,
    pos: usize,
}

/// Parse a full HCL document into its top-level blocks.
pub fn parse_document(src: &str) -> Vec<Block> {
    // Strip a UTF-8 BOM (common on Windows-authored files) so byte indexing
    // starts on a char boundary.
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    let mut p = Parser {
        s: src.as_bytes(),
        src,
        pos: 0,
    };
    let (_attrs, blocks) = p.parse_body(true, 0);
    blocks
}

impl<'a> Parser<'a> {
    fn peek(&self) -> u8 {
        if self.pos < self.s.len() {
            self.s[self.pos]
        } else {
            0
        }
    }
    fn peek2(&self) -> u8 {
        if self.pos + 1 < self.s.len() {
            self.s[self.pos + 1]
        } else {
            0
        }
    }

    /// Advance past one full UTF-8 codepoint, so `pos` never lands inside a
    /// multibyte char (which would make a later str slice panic).
    fn advance_char(&mut self) {
        self.pos = (self.pos + utf8_len(self.peek()).max(1)).min(self.s.len());
    }

    /// Skip spaces, tabs and CR (not newline) plus comments.
    fn skip_inline(&mut self) {
        loop {
            match self.peek() {
                b' ' | b'\t' | b'\r' => self.pos += 1,
                b'#' => self.skip_line_comment(),
                b'/' if self.peek2() == b'/' => self.skip_line_comment(),
                b'/' if self.peek2() == b'*' => self.skip_block_comment(),
                _ => break,
            }
        }
    }
    /// Skip all whitespace (incl newlines) and comments.
    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                b'#' => self.skip_line_comment(),
                b'/' if self.peek2() == b'/' => self.skip_line_comment(),
                b'/' if self.peek2() == b'*' => self.skip_block_comment(),
                _ => break,
            }
        }
    }
    fn skip_line_comment(&mut self) {
        while self.pos < self.s.len() && self.s[self.pos] != b'\n' {
            self.pos += 1;
        }
    }
    fn skip_block_comment(&mut self) {
        self.pos += 2;
        while self.pos < self.s.len() {
            if self.peek() == b'*' && self.peek2() == b'/' {
                self.pos += 2;
                break;
            }
            self.pos += 1;
        }
    }

    fn read_ident(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.s.len() {
            let c = self.s[self.pos];
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'.' {
                self.pos += 1;
            } else {
                break;
            }
        }
        self.src[start..self.pos].to_string()
    }

    /// 1-based source line containing the byte at `offset`.
    fn line_at(&self, offset: usize) -> u32 {
        let end = offset.min(self.s.len());
        1 + self.s[..end].iter().filter(|&&c| c == b'\n').count() as u32
    }

    fn parse_body(&mut self, top: bool, depth: usize) -> (Vec<(String, Value)>, Vec<Block>) {
        // Depth guard: stop descending past the cap. The caller already consumed
        // the opening `{`, and its loop advances on every iteration, so bailing
        // here can't loop — it just drops the over-deep subtree.
        if depth > fact_model::limits::MAX_HCL_DEPTH {
            return (Vec::new(), Vec::new());
        }
        let mut attrs = Vec::new();
        let mut blocks = Vec::new();
        loop {
            self.skip_trivia();
            if self.pos >= self.s.len() {
                break;
            }
            if !top && self.peek() == b'}' {
                break;
            }
            // Byte offset where this declaration begins — used to recover the
            // source line if it turns out to be a block.
            let tok_start = self.pos;
            // An attribute key may be a quoted string in object/map values
            // (e.g. `{ "_S3_BUCKET_ID_" = ... }`, common in real Terraform).
            // Without this the quoted key derails parsing of the whole block.
            let ident = if self.peek() == b'"' {
                self.read_string()
            } else {
                self.read_ident()
            };
            if ident.is_empty() {
                self.advance_char(); // unexpected char; advance to guarantee progress
                continue;
            }
            self.skip_inline();
            // HCL accepts `=` for attributes; object/map literals also accept `:`
            // (JSON style). Treat both as attribute separators.
            if self.peek() == b'=' || self.peek() == b':' {
                self.pos += 1;
                let v = self.parse_value(depth + 1);
                attrs.push((ident, v));
            } else {
                // block: read labels until '{'
                let mut labels = Vec::new();
                loop {
                    self.skip_trivia();
                    match self.peek() {
                        b'{' => {
                            self.pos += 1;
                            break;
                        }
                        b'"' => labels.push(self.read_string()),
                        // Backstop: a block body opens with `{`. Hitting `}` or a
                        // top-level `=`/`:` means we misread — stop here rather than
                        // run away consuming following declarations.
                        b'}' | b'=' | b':' | 0 => break,
                        _ => {
                            let lbl = self.read_ident();
                            if lbl.is_empty() {
                                self.advance_char();
                            } else {
                                labels.push(lbl);
                            }
                        }
                    }
                }
                let (a, b) = self.parse_body(false, depth + 1);
                if self.peek() == b'}' {
                    self.pos += 1;
                }
                blocks.push(Block {
                    typ: ident,
                    labels,
                    attrs: a,
                    blocks: b,
                    line: self.line_at(tok_start),
                });
            }
        }
        (attrs, blocks)
    }

    fn parse_value(&mut self, depth: usize) -> Value {
        self.skip_inline();
        // Depth guard: refuse to recurse deeper. Consume one byte so the caller
        // (e.g. read_list's loop) is guaranteed to make progress and can't spin.
        if depth > fact_model::limits::MAX_HCL_DEPTH {
            self.advance_char();
            return Value::Raw(String::new());
        }
        match self.peek() {
            b'"' => Value::Str(self.read_string()),
            // `[for ...]` / `{for ...}` comprehensions aren't plain collections —
            // their `for ... : k => v if ...` body would derail structural
            // parsing (and the stray `}` used to swallow following blocks).
            // They're not security-relevant, so capture them opaquely.
            b'[' if self.starts_comprehension() => Value::Raw(self.read_balanced()),
            b'[' => self.read_list(depth),
            b'{' if self.starts_comprehension() => Value::Raw(self.read_balanced()),
            b'{' => {
                self.pos += 1;
                let (a, _b) = self.parse_body(false, depth + 1);
                if self.peek() == b'}' {
                    self.pos += 1;
                }
                Value::Obj(a)
            }
            b'<' if self.peek2() == b'<' => Value::Str(self.read_heredoc()),
            _ => Value::Raw(self.read_raw_value()),
        }
    }

    /// Peek (without advancing) whether the `{`/`[` at the cursor opens a `for`
    /// comprehension, i.e. the first token after the bracket is the `for` keyword.
    fn starts_comprehension(&self) -> bool {
        let mut i = self.pos + 1; // past the opening bracket
        // skip inline whitespace/newlines (no comments — rare right here)
        while i < self.s.len() && matches!(self.s[i], b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        }
        self.s[i..].starts_with(b"for")
            && self
                .s
                .get(i + 3)
                .map(|c| !c.is_ascii_alphanumeric() && *c != b'_')
                .unwrap_or(true)
    }

    /// Read a balanced `{...}` or `[...]` span as raw text (honouring strings and
    /// nesting). Used for comprehensions we don't structurally interpret.
    fn read_balanced(&mut self) -> String {
        let start = self.pos;
        let mut depth: i32 = 0;
        while self.pos < self.s.len() {
            match self.s[self.pos] {
                b'"' => {
                    self.skip_raw_string();
                    continue;
                }
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        self.pos += 1;
                        break;
                    }
                }
                _ => {}
            }
            self.pos += 1;
        }
        self.src[start..self.pos].trim().to_string()
    }

    fn read_string(&mut self) -> String {
        // assumes current char is '"'
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.s.len() {
            let c = self.s[self.pos];
            if c == b'\\' {
                // keep the escaped char literally
                if self.pos + 1 < self.s.len() {
                    out.push(self.s[self.pos] as char);
                    out.push(self.s[self.pos + 1] as char);
                    self.pos += 2;
                } else {
                    self.pos += 1;
                }
            } else if c == b'$' && self.peek2() == b'{' {
                // interpolation ${ ... } — copy verbatim, balancing braces
                let start = self.pos;
                self.pos += 2;
                let mut depth = 1;
                while self.pos < self.s.len() && depth > 0 {
                    match self.s[self.pos] {
                        b'{' => depth += 1,
                        b'}' => depth -= 1,
                        _ => {}
                    }
                    self.pos += 1;
                }
                out.push_str(&self.src[start..self.pos]);
            } else if c == b'"' {
                self.pos += 1;
                break;
            } else {
                // advance by one UTF-8 codepoint
                let ch_len = utf8_len(c);
                let end = (self.pos + ch_len).min(self.s.len());
                out.push_str(&self.src[self.pos..end]);
                self.pos = end;
            }
        }
        out
    }

    fn read_list(&mut self, depth: usize) -> Value {
        self.pos += 1; // '['
        let mut items = Vec::new();
        loop {
            self.skip_trivia();
            match self.peek() {
                b']' => {
                    self.pos += 1;
                    break;
                }
                0 => break,
                b',' => {
                    self.pos += 1;
                }
                _ => items.push(self.parse_value(depth + 1)),
            }
        }
        Value::List(items)
    }

    fn read_heredoc(&mut self) -> String {
        self.pos += 2; // '<<'
        if self.peek() == b'~' {
            self.pos += 1;
        }
        let delim = self.read_ident();
        // skip to end of the opening line
        while self.pos < self.s.len() && self.s[self.pos] != b'\n' {
            self.pos += 1;
        }
        if self.peek() == b'\n' {
            self.pos += 1;
        }
        let body_start = self.pos;
        // read lines until one trimmed equals the delimiter
        loop {
            let line_start = self.pos;
            while self.pos < self.s.len() && self.s[self.pos] != b'\n' {
                self.pos += 1;
            }
            let line = self.src[line_start..self.pos].trim();
            if line == delim || self.pos >= self.s.len() {
                let body = self.src[body_start..line_start].to_string();
                if self.peek() == b'\n' {
                    self.pos += 1;
                }
                return body;
            }
            if self.peek() == b'\n' {
                self.pos += 1;
            }
        }
    }

    /// Read a raw expression value: until a newline (or `,`/`]`/`}`) at bracket
    /// depth 0, honouring nested () [] {} and strings (so `jsonencode({ ... })`
    /// spanning lines is captured whole).
    fn read_raw_value(&mut self) -> String {
        let start = self.pos;
        let mut depth: i32 = 0;
        while self.pos < self.s.len() {
            let c = self.s[self.pos];
            match c {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                b'"' => {
                    self.skip_raw_string();
                    continue;
                }
                b'\n' if depth == 0 => break,
                b',' if depth == 0 => break,
                b'#' if depth == 0 => break,
                _ => {}
            }
            self.pos += 1;
        }
        self.src[start..self.pos].trim().to_string()
    }

    fn skip_raw_string(&mut self) {
        self.pos += 1; // opening quote
        while self.pos < self.s.len() {
            match self.s[self.pos] {
                b'\\' => self.pos += 2,
                b'"' => {
                    self.pos += 1;
                    break;
                }
                _ => self.pos += 1,
            }
        }
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else if first >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resource_with_nested_block() {
        let src = r#"
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
        let blocks = parse_document(src);
        assert_eq!(blocks.len(), 1);
        let sg = &blocks[0];
        assert_eq!(sg.typ, "resource");
        assert_eq!(sg.labels, vec!["aws_security_group", "web"]);
        let ing = sg.child_blocks("ingress").next().unwrap();
        assert!(ing.attr("cidr_blocks").unwrap().contains_scalar("0.0.0.0/0"));
    }

    #[test]
    fn parses_heredoc_policy() {
        let src = "resource \"aws_iam_policy\" \"p\" {\n  policy = <<EOT\n{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\"}]}\nEOT\n}\n";
        let blocks = parse_document(src);
        let pol = blocks[0].attr("policy").unwrap().text();
        assert!(pol.contains("\"Action\":\"*\""));
    }

    #[test]
    fn quoted_object_keys_do_not_derail_following_blocks() {
        // Real-world Terraform (e.g. terraform-aws-modules) uses quoted map keys.
        // This used to swallow every block after it; the resource must survive.
        let src = r#"
locals {
  placeholders = {
    "_S3_BUCKET_ID_"   = "id"
    "_AWS_ACCOUNT_ID_" = "acct"
  }
}
resource "aws_s3_bucket" "data" {
  acl = "public-read"
}
"#;
        let blocks = parse_document(src);
        let res = blocks.iter().find(|b| b.typ == "resource");
        assert!(res.is_some(), "resource after quoted-key map was dropped");
        let res = res.unwrap();
        assert_eq!(res.labels, vec!["aws_s3_bucket", "data"]);
        assert!(res.attr("acl").unwrap().contains_scalar("public-read"));
    }

    #[test]
    fn for_comprehensions_do_not_derail_following_blocks() {
        // `{ for ... }` and `[ for ... ]` are pervasive in real Terraform and
        // used to swallow every block after them. The resource must survive,
        // and the comprehension is captured opaquely (not as a structural obj).
        let src = r#"
locals {
  m = { for k, v in var.in : k => v if v.on }
  l = [for p in var.ports : p if p > 0]
}
resource "aws_security_group" "open" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
        let blocks = parse_document(src);
        let res = blocks.iter().find(|b| b.typ == "resource");
        assert!(res.is_some(), "resource after a for-comprehension was dropped");
        assert_eq!(res.unwrap().labels, vec!["aws_security_group", "open"]);
    }

    #[test]
    fn deeply_nested_blocks_do_not_overflow_the_stack() {
        // Before the depth guard this aborted with STATUS_STACK_OVERFLOW.
        let n = 50_000;
        let src = String::from("resource \"x\" \"y\" {\n")
            + &"b {\n".repeat(n)
            + &"}\n".repeat(n)
            + "}\n";
        // The contract is "terminates without crashing"; the over-deep subtree
        // is dropped, so we only assert it parsed the top-level resource.
        let blocks = parse_document(&src);
        assert_eq!(blocks[0].typ, "resource");
    }

    #[test]
    fn deeply_nested_lists_do_not_overflow_the_stack() {
        let n = 50_000;
        let src = String::from("resource \"x\" \"y\" {\n  v = ")
            + &"[".repeat(n)
            + &"]".repeat(n)
            + "\n}\n";
        let blocks = parse_document(&src);
        assert_eq!(blocks[0].typ, "resource");
    }
}
