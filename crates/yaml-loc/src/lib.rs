//! Source-line index for YAML documents.
//!
//! Walks yaml-rust2's *marked* event stream and records, for every node, the
//! dotted/indexed path to it (e.g. `services.web.ports[0]`) mapped to its
//! 1-based source line. The YAML-based parsers build source paths with this
//! exact convention, so a parser can attach a line to an entity by looking up
//! the path string it already computes — no change to its tree-walking logic.
//!
//! Deterministic and panic-free: malformed YAML yields a partial map.

use std::collections::BTreeMap;

use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::Marker;

/// Map from node path → 1-based source line for the given YAML text.
///
/// Paths use `.` between mapping keys and `[i]` for sequence elements, rooted
/// at the document (e.g. `jobs.build.steps[2]`). Multi-document streams share
/// one map (last write wins on path collisions across docs — rare in practice).
pub fn line_index(input: &str) -> BTreeMap<String, u32> {
    let mut recv = Indexer::default();
    // yaml-rust2 wants a char iterator; load all documents in the stream.
    let mut parser = Parser::new(input.chars());
    // Ignore scan errors: we keep whatever paths were recorded before the fault.
    let _ = parser.load(&mut recv, true);
    recv.lines
}

/// Per-document line indices for a multi-document YAML stream, in document order.
///
/// Kubernetes manifests are commonly multi-document (`---` separated). A single
/// merged [`line_index`] map collides identical paths across documents (e.g.
/// `kind`, `metadata.name`) — last write wins — so callers that need per-document
/// lines should index by document position here instead.
pub fn line_index_per_doc(input: &str) -> Vec<BTreeMap<String, u32>> {
    let mut recv = DocIndexer::default();
    let mut parser = Parser::new(input.chars());
    let _ = parser.load(&mut recv, true);
    recv.finish()
}

/// Splits the marked event stream on document boundaries, running a fresh
/// [`Indexer`] per document so each gets its own path→line map.
#[derive(Default)]
struct DocIndexer {
    docs: Vec<BTreeMap<String, u32>>,
    cur: Option<Indexer>,
}

impl DocIndexer {
    fn finish(mut self) -> Vec<BTreeMap<String, u32>> {
        if let Some(cur) = self.cur.take() {
            self.docs.push(cur.lines);
        }
        self.docs
    }
}

impl MarkedEventReceiver for DocIndexer {
    fn on_event(&mut self, event: Event, mark: Marker) {
        match event {
            Event::DocumentStart => {
                if let Some(cur) = self.cur.take() {
                    self.docs.push(cur.lines);
                }
                self.cur = Some(Indexer::default());
            }
            Event::DocumentEnd => {
                if let Some(cur) = self.cur.take() {
                    self.docs.push(cur.lines);
                }
            }
            other => {
                if let Some(cur) = self.cur.as_mut() {
                    cur.on_event(other, mark);
                }
            }
        }
    }
}

enum Frame {
    /// Inside a mapping. `path` is the path of the mapping node itself.
    Map { path: String, key: String, expecting_key: bool },
    /// Inside a sequence. `path` is the path of the sequence node itself.
    Seq { path: String, idx: usize },
}

#[derive(Default)]
struct Indexer {
    lines: BTreeMap<String, u32>,
    stack: Vec<Frame>,
}

impl Indexer {
    /// Path of the slot about to be filled in the current top container.
    fn slot_path(&self) -> String {
        match self.stack.last() {
            None => String::new(),
            Some(Frame::Map { path, key, .. }) => join(path, key),
            Some(Frame::Seq { path, idx }) => format!("{path}[{idx}]"),
        }
    }

    /// A non-scalar value (map/seq/alias) just finished filling the current
    /// slot — advance the parent so the next key/element is expected.
    fn advance_after_value(&mut self) {
        match self.stack.last_mut() {
            Some(Frame::Map { expecting_key, .. }) => *expecting_key = true,
            Some(Frame::Seq { idx, .. }) => *idx += 1,
            None => {}
        }
    }
}

fn join(parent: &str, key: &str) -> String {
    if parent.is_empty() {
        key.to_string()
    } else {
        format!("{parent}.{key}")
    }
}

impl MarkedEventReceiver for Indexer {
    fn on_event(&mut self, event: Event, mark: Marker) {
        match event {
            Event::Scalar(val, ..) => match self.stack.last_mut() {
                Some(Frame::Map { path, key, expecting_key }) => {
                    if *expecting_key {
                        *key = val;
                        let p = join(path, key);
                        self.lines.entry(p).or_insert(mark.line() as u32);
                        *expecting_key = false;
                    } else {
                        // value scalar for the current key — already recorded;
                        // ready for the next key.
                        *expecting_key = true;
                    }
                }
                Some(Frame::Seq { path, idx }) => {
                    let p = format!("{path}[{idx}]");
                    self.lines.entry(p).or_insert(mark.line() as u32);
                    *idx += 1;
                }
                None => {}
            },
            Event::MappingStart(..) => {
                let path = self.slot_path();
                self.lines.entry(path.clone()).or_insert(mark.line() as u32);
                self.stack.push(Frame::Map { path, key: String::new(), expecting_key: true });
            }
            Event::SequenceStart(..) => {
                let path = self.slot_path();
                self.lines.entry(path.clone()).or_insert(mark.line() as u32);
                self.stack.push(Frame::Seq { path, idx: 0 });
            }
            Event::MappingEnd | Event::SequenceEnd => {
                self.stack.pop();
                self.advance_after_value();
            }
            Event::Alias(_) => {
                // An alias fills a slot like a value would.
                self.advance_after_value();
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_nested_map_and_sequence_paths() {
        // line 1 is the leading newline; content starts at line 2.
        let src = "
services:
  web:
    image: nginx
    ports:
      - 8080:80
      - 9090:90
";
        let idx = line_index(src);
        assert_eq!(idx.get("services").copied(), Some(2));
        assert_eq!(idx.get("services.web").copied(), Some(3));
        assert_eq!(idx.get("services.web.image").copied(), Some(4));
        assert_eq!(idx.get("services.web.ports").copied(), Some(5));
        assert_eq!(idx.get("services.web.ports[0]").copied(), Some(6));
        assert_eq!(idx.get("services.web.ports[1]").copied(), Some(7));
    }

    #[test]
    fn malformed_yaml_does_not_panic() {
        let _ = line_index("a: [unterminated\n  : :");
        let _ = line_index_per_doc("a: [unterminated\n  : :");
    }

    #[test]
    fn per_doc_index_keeps_documents_separate() {
        // Two docs sharing the path `kind` — a merged map would lose the first.
        let src = "\
kind: Pod
metadata:
  name: a
---
kind: Service
metadata:
  name: b
";
        let docs = line_index_per_doc(src);
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].get("kind").copied(), Some(1));
        assert_eq!(docs[0].get("metadata.name").copied(), Some(3));
        assert_eq!(docs[1].get("kind").copied(), Some(5));
        assert_eq!(docs[1].get("metadata.name").copied(), Some(7));
    }
}
