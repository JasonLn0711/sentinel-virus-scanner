use std::collections::{HashMap, HashSet, VecDeque};

use serde::Serialize;

use crate::signatures::{PatternSignatureMatcher, SignatureSummary};

#[derive(Debug, Clone, Serialize)]
pub struct PatternMatch {
    pub signature: SignatureSummary,
    pub matcher: String,
    pub pattern_offset: usize,
    pub pattern_bytes: usize,
}

#[derive(Debug, Clone)]
struct Node {
    transitions: HashMap<u8, usize>,
    failure: usize,
    outputs: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct PatternEngine {
    patterns: Vec<PatternSignatureMatcher>,
    nodes: Vec<Node>,
}

impl PatternEngine {
    pub fn new(patterns: Vec<PatternSignatureMatcher>) -> Self {
        let mut engine = Self {
            patterns,
            nodes: vec![Node {
                transitions: HashMap::new(),
                failure: 0,
                outputs: Vec::new(),
            }],
        };
        engine.build_trie();
        engine.build_failure_links();
        engine
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    pub fn state_count(&self) -> usize {
        self.nodes.len()
    }

    #[cfg(test)]
    pub fn scan(&self, data: &[u8]) -> Vec<PatternMatch> {
        let mut scanner = self.stream();
        scanner.feed(data);
        scanner.finish()
    }

    pub fn stream(&self) -> PatternStreamScanner<'_> {
        PatternStreamScanner {
            engine: self,
            state: 0,
            seen: HashSet::new(),
            offset: 0,
            matches: Vec::new(),
        }
    }

    fn transition(&self, mut state: usize, byte: u8) -> usize {
        while state != 0 && !self.nodes[state].transitions.contains_key(&byte) {
            state = self.nodes[state].failure;
        }
        self.nodes[state]
            .transitions
            .get(&byte)
            .copied()
            .unwrap_or(0)
    }
}

pub struct PatternStreamScanner<'a> {
    engine: &'a PatternEngine,
    state: usize,
    seen: HashSet<usize>,
    offset: usize,
    matches: Vec<PatternMatch>,
}

impl PatternStreamScanner<'_> {
    pub fn feed(&mut self, data: &[u8]) {
        for (chunk_position, byte) in data.iter().copied().enumerate() {
            self.state = self.engine.transition(self.state, byte);
            let absolute_position = self.offset + chunk_position;

            for pattern_index in self.engine.nodes[self.state].outputs.iter().copied() {
                if self.seen.insert(pattern_index) {
                    let pattern = &self.engine.patterns[pattern_index];
                    let offset = absolute_position + 1 - pattern.pattern.len();
                    self.matches.push(PatternMatch {
                        signature: pattern.signature.clone(),
                        matcher: pattern.matcher_type.clone(),
                        pattern_offset: offset,
                        pattern_bytes: pattern.pattern.len(),
                    });
                }
            }
        }

        self.offset += data.len();
    }

    pub fn finish(self) -> Vec<PatternMatch> {
        self.matches
    }
}

impl PatternEngine {
    fn build_trie(&mut self) {
        for (pattern_index, pattern) in self.patterns.iter().enumerate() {
            let mut state = 0;
            for byte in &pattern.pattern {
                let next = if let Some(next) = self.nodes[state].transitions.get(byte).copied() {
                    next
                } else {
                    let next = self.nodes.len();
                    self.nodes[state].transitions.insert(*byte, next);
                    self.nodes.push(Node {
                        transitions: HashMap::new(),
                        failure: 0,
                        outputs: Vec::new(),
                    });
                    next
                };
                state = next;
            }
            self.nodes[state].outputs.push(pattern_index);
        }
    }

    fn build_failure_links(&mut self) {
        let mut queue = VecDeque::new();
        let root_children: Vec<usize> = self.nodes[0].transitions.values().copied().collect();
        for child in root_children {
            self.nodes[child].failure = 0;
            queue.push_back(child);
        }

        while let Some(state) = queue.pop_front() {
            let transitions: Vec<(u8, usize)> = self.nodes[state]
                .transitions
                .iter()
                .map(|(byte, next)| (*byte, *next))
                .collect();

            for (byte, next_state) in transitions {
                queue.push_back(next_state);
                let mut fallback = self.nodes[state].failure;
                while fallback != 0 && !self.nodes[fallback].transitions.contains_key(&byte) {
                    fallback = self.nodes[fallback].failure;
                }
                let failure = self.nodes[fallback]
                    .transitions
                    .get(&byte)
                    .copied()
                    .unwrap_or(0);
                self.nodes[next_state].failure = failure;

                let inherited = self.nodes[failure].outputs.clone();
                self.nodes[next_state].outputs.extend(inherited);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::signatures::{PatternSignatureMatcher, SignatureSummary};

    use super::PatternEngine;

    #[test]
    fn finds_pattern_offset() {
        let pattern = PatternSignatureMatcher {
            signature: SignatureSummary {
                id: "sig".to_string(),
                name: "Signature".to_string(),
                category: "safe".to_string(),
                severity: "critical".to_string(),
            },
            matcher_type: "hex_pattern".to_string(),
            pattern: b"ABC".to_vec(),
        };
        let engine = PatternEngine::new(vec![pattern]);
        let matches = engine.scan(b"xxABCxx");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_offset, 2);
    }

    #[test]
    fn stream_preserves_state_between_chunks() {
        let pattern = PatternSignatureMatcher {
            signature: SignatureSummary {
                id: "sig".to_string(),
                name: "Signature".to_string(),
                category: "safe".to_string(),
                severity: "critical".to_string(),
            },
            matcher_type: "hex_pattern".to_string(),
            pattern: b"ABCDE".to_vec(),
        };
        let engine = PatternEngine::new(vec![pattern]);
        let mut scanner = engine.stream();

        scanner.feed(b"xxAB");
        scanner.feed(b"CDEyy");
        let matches = scanner.finish();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_offset, 2);
    }
}
