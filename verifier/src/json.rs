//! A JSON reader that only accepts canonical form.
//!
//! This is not a general parser and must never become one. It refuses
//! whitespace, unsorted keys, duplicate keys, numbers, non-minimal escapes
//! and trailing bytes. Every refusal here is a document that two
//! implementations might have read differently, which is exactly the
//! situation content addressing exists to prevent.
//!
//! Nodes remember the byte range they were parsed from. That lets the
//! verifier hash a value by taking the original bytes rather than
//! re-serialising it, so a disagreement between our writer and our reader
//! cannot hide.

use std::ops::Range;

#[derive(Debug)]
pub enum Value {
    Null,
    // The format permits booleans, so the parser must accept them, even
    // though no claim type reads one yet. Dropping the payload, as the
    // compiler suggests, would make `true` and `false` parse to the same
    // value: two different documents, one reading.
    #[allow(dead_code)]
    Bool(bool),
    Str(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

#[derive(Debug)]
pub struct Node {
    pub value: Value,
    pub span: Range<usize>,
}

impl Node {
    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Vec<(String, Node)>> {
        match &self.value {
            Value::Object(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Node>> {
        match &self.value {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Refuse a key nobody reads.
    ///
    /// A method on `Node` rather than a helper in one module, because
    /// the rule applies at every level of a document and a rule that
    /// lives next to one caller is a rule the next caller forgets. The
    /// bundle's top level has always refused unknown fields; claims,
    /// subjects, payloads and the objects nested inside payloads do too.
    ///
    /// What it buys, in one line: a field nothing checks is a sentence
    /// addressed to a human reader with no verifier behind it, and this
    /// format exists so that what a reader sees is what a verifier
    /// checked.
    pub fn closed_keys(&self, allowed: &[&str], ctx: &str) -> Result<(), String> {
        for (key, _) in self
            .as_object()
            .ok_or_else(|| format!("{ctx} must be an object"))?
        {
            if !allowed.contains(&key.as_str()) {
                return Err(format!("{ctx}: unknown field `{key}`"));
            }
        }
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&Node> {
        self.as_object()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// Field lookup that explains itself when it fails.
    pub fn field(&self, key: &str, ctx: &str) -> Result<&Node, String> {
        self.get(key)
            .ok_or_else(|| format!("{ctx}: missing field `{key}`"))
    }

    pub fn str_field(&self, key: &str, ctx: &str) -> Result<&str, String> {
        self.field(key, ctx)?
            .as_str()
            .ok_or_else(|| format!("{ctx}: field `{key}` must be a string"))
    }
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

pub fn parse(input: &str) -> Result<Node, String> {
    if input.starts_with('\u{feff}') {
        return Err("byte order mark is not allowed".into());
    }
    let mut parser = Parser {
        src: input.as_bytes(),
        pos: 0,
    };
    let node = parser.value()?;

    // One optional trailing newline, and nothing else at all.
    let rest = &parser.src[parser.pos..];
    match rest {
        [] | [b'\n'] => Ok(node),
        _ => Err(format!("trailing bytes after the document at offset {}", parser.pos)),
    }
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Result<u8, String> {
        self.src
            .get(self.pos)
            .copied()
            .ok_or_else(|| "document ended early".to_string())
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        let found = self.peek()?;
        if found != byte {
            return Err(format!(
                "expected `{}` at offset {}, found `{}`",
                byte as char, self.pos, found as char
            ));
        }
        self.pos += 1;
        Ok(())
    }

    fn value(&mut self) -> Result<Node, String> {
        let start = self.pos;
        let byte = self.peek()?;
        let value = match byte {
            b'{' => self.object()?,
            b'[' => self.array()?,
            b'"' => Value::Str(self.string()?),
            b't' => {
                self.literal("true")?;
                Value::Bool(true)
            }
            b'f' => {
                self.literal("false")?;
                Value::Bool(false)
            }
            b'n' => {
                self.literal("null")?;
                Value::Null
            }
            b'0'..=b'9' | b'-' => {
                return Err(format!(
                    "numbers are not allowed in canonical form (offset {}); \
                     quantities must be decimal strings",
                    self.pos
                ))
            }
            b' ' | b'\t' | b'\n' | b'\r' => {
                return Err(format!("whitespace at offset {}", self.pos))
            }
            other => {
                return Err(format!(
                    "unexpected byte `{}` at offset {}",
                    other as char, self.pos
                ))
            }
        };
        Ok(Node {
            value,
            span: start..self.pos,
        })
    }

    fn literal(&mut self, word: &str) -> Result<(), String> {
        if self.src[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(format!("malformed literal at offset {}", self.pos))
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.expect(b'{')?;
        let mut entries: Vec<(String, Node)> = Vec::new();
        if self.peek()? == b'}' {
            self.pos += 1;
            return Ok(Value::Object(entries));
        }
        loop {
            let key_at = self.pos;
            let key = self.string()?;
            check_key(&key, key_at)?;
            if let Some((previous, _)) = entries.last() {
                // Sorted and unique, by bytes. Both matter: unsorted keys
                // mean two encodings of one document, duplicates mean two
                // readers can disagree about which value wins.
                if previous.as_bytes() >= key.as_bytes() {
                    return Err(format!(
                        "keys out of order or repeated at offset {key_at}: \
                         `{previous}` then `{key}`"
                    ));
                }
            }
            self.expect(b':')?;
            let value = self.value()?;
            entries.push((key, value));
            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    return Ok(Value::Object(entries));
                }
                other => {
                    return Err(format!(
                        "expected `,` or `}}` at offset {}, found `{}`",
                        self.pos, other as char
                    ))
                }
            }
        }
    }

    fn array(&mut self) -> Result<Value, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        if self.peek()? == b']' {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            match self.peek()? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                other => {
                    return Err(format!(
                        "expected `,` or `]` at offset {}, found `{}`",
                        self.pos, other as char
                    ))
                }
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = self.peek()?;
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let escape = self.peek()?;
                    self.pos += 1;
                    let ch = match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => return Err("`\\/` is not minimal escaping".into()),
                        b'n' => '\n',
                        b't' => '\t',
                        b'r' => '\r',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'u' => self.unicode_escape()?,
                        other => {
                            return Err(format!("unknown escape `\\{}`", other as char))
                        }
                    };
                    out.push(ch);
                }
                0x00..=0x1f => {
                    return Err(format!("raw control byte at offset {}", self.pos))
                }
                _ => {
                    // Copy one whole UTF-8 sequence. The input was already
                    // validated as UTF-8, so boundaries are trustworthy.
                    let start = self.pos;
                    self.pos += 1;
                    while self.pos < self.src.len() && (self.src[self.pos] & 0xc0) == 0x80 {
                        self.pos += 1;
                    }
                    out.push_str(
                        std::str::from_utf8(&self.src[start..self.pos])
                            .map_err(|_| "invalid UTF-8 in string".to_string())?,
                    );
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        if self.pos + 4 > self.src.len() {
            return Err("truncated \\u escape".into());
        }
        let hex = std::str::from_utf8(&self.src[self.pos..self.pos + 4])
            .map_err(|_| "invalid \\u escape".to_string())?;
        let code = u32::from_str_radix(hex, 16).map_err(|_| "invalid \\u escape".to_string())?;
        self.pos += 4;
        if code >= 0x20 {
            // Anything printable must appear literally, or one character
            // would have two spellings.
            return Err(format!("non-minimal escape \\u{hex}"));
        }
        char::from_u32(code).ok_or_else(|| "invalid \\u escape".to_string())
    }
}

fn check_key(key: &str, at: usize) -> Result<(), String> {
    if key.is_empty() {
        return Err(format!("empty object key at offset {at}"));
    }
    for byte in key.bytes() {
        let ok = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-');
        if !ok {
            return Err(format!("key `{key}` at offset {at} uses a byte outside [A-Za-z0-9._:-]"));
        }
    }
    Ok(())
}
