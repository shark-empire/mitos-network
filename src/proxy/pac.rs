//! A PAC (proxy auto-config) evaluator: fetches a `FindProxyForURL()`
//! script over plain HTTP and actually runs it, rather than just
//! storing its URL for something else to interpret someday.
//!
//! PAC files are JavaScript, but a full JS engine is a dependency this
//! crate deliberately doesn't carry (same reasoning as hand-rolling
//! netlink instead of a wrapper crate). What's implemented here is a
//! small, self-contained interpreter for the *subset* real-world PAC
//! scripts actually use: `var`, `if`/`else`, `return`, string/number/
//! boolean literals and concatenation, comparisons, `&&`/`||`/`!`,
//! function declarations and calls, plus the standard PAC helper
//! functions (`isPlainHostName`, `dnsDomainIs`, `shExpMatch`,
//! `isInNet`, ...) implemented natively rather than interpreted.
//!
//! Deliberately NOT supported: loops (`for`/`while`), arrays/objects,
//! and general JS beyond the above. This isn't just a scope cut -- PAC
//! content comes from the network (WPAD/DHCP, or wherever `pac_url`
//! points), so it's untrusted input a hostile network could serve.
//! Without loops, every PAC script this interpreter accepts is
//! statically guaranteed to terminate (its call graph is finite, and
//! [`MAX_CALL_DEPTH`] bounds recursion) -- there's no expression that
//! can make evaluation run away, which matters a lot more here than
//! supporting every corner of the language would.
//!
//! `weekdayRange`/`dateRange`/`timeRange` are evaluated in UTC, not
//! the client's local time zone: correct local-time handling needs a
//! tzdata parser, which is more machinery than these three
//! rarely-used functions justify pulling in.

use crate::errors::{NetworkError, Result};
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_CALL_DEPTH: usize = 64;
/// PAC files are typically a few KB; anything past this is almost
/// certainly not a well-formed PAC script, and reading it all into
/// memory isn't worth doing before finding that out.
const MAX_PAC_SIZE: usize = 1024 * 1024;

// ---- Fetching -------------------------------------------------------

/// Retrieves a PAC script over plain HTTP. TLS is deliberately not
/// supported (no TLS client in this crate at all) -- in practice
/// PAC/WPAD deployment is overwhelmingly plain HTTP by convention, so
/// this covers the real world rather than the spec's full generality.
pub fn fetch(url: &str) -> Result<String> {
    let (host, port, path) = parse_http_url(url)?;
    let timeout = Duration::from_secs(10);
    let mut stream = std::net::TcpStream::connect((host.as_str(), port))
        .map_err(|e| NetworkError::Other(format!("connecting to PAC server {host}:{port}: {e}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(NetworkError::Io)?;

    use std::io::{Read, Write};
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mitos-network\r\nAccept: application/x-ns-proxy-autoconfig, */*\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| NetworkError::Other(format!("sending PAC request: {e}")))?;

    let mut raw = Vec::new();
    stream
        .take(MAX_PAC_SIZE as u64 + 8192) // headers + a bounded body
        .read_to_end(&mut raw)
        .map_err(|e| NetworkError::Other(format!("reading PAC response: {e}")))?;
    let raw = String::from_utf8_lossy(&raw);
    let (headers, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| NetworkError::Other("malformed HTTP response fetching PAC".into()))?;

    let status_line = headers.lines().next().unwrap_or("");
    if !status_line
        .splitn(3, ' ')
        .nth(1)
        .is_some_and(|code| code == "200")
    {
        return Err(NetworkError::Other(format!(
            "PAC server returned: {status_line}"
        )));
    }

    let body = if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body)
    } else {
        body.to_string()
    };
    if body.len() > MAX_PAC_SIZE {
        return Err(NetworkError::Other("PAC file exceeds size limit".into()));
    }
    Ok(body)
}

fn parse_http_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        NetworkError::Other("only http:// PAC URLs are supported (no TLS client available)".into())
    })?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| NetworkError::Other(format!("invalid port in PAC URL: '{p}'")))?,
        ),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return Err(NetworkError::Other("PAC URL has no host".into()));
    }
    Ok((host, port, path))
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let Some((size_line, tail)) = rest.split_once("\r\n") else {
            break;
        };
        let size_line = size_line.split(';').next().unwrap_or(size_line).trim();
        let Ok(size) = usize::from_str_radix(size_line, 16) else {
            break;
        };
        if size == 0 {
            break;
        }
        if tail.len() < size {
            break;
        }
        out.push_str(&tail[..size]);
        rest = tail
            .get(size..)
            .and_then(|s| s.strip_prefix("\r\n"))
            .unwrap_or("");
    }
    out
}

// ---- Values -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
}

impl Value {
    fn truthy(&self) -> bool {
        match self {
            Value::Str(s) => !s.is_empty(),
            Value::Num(n) => *n != 0.0,
            Value::Bool(b) => *b,
            Value::Null => false,
        }
    }

    fn as_string(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Num(n) => {
                if n.fract() == 0.0 {
                    format!("{n:.0}")
                } else {
                    n.to_string()
                }
            }
            Value::Bool(b) => b.to_string(),
            Value::Null => "null".to_string(),
        }
    }

    fn as_num(&self) -> f64 {
        match self {
            Value::Num(n) => *n,
            Value::Str(s) => s.trim().parse().unwrap_or(f64::NAN),
            Value::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            Value::Null => 0.0,
        }
    }
}

// ---- Tokenizer ----------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Num(f64),
    LParen,
    RParen,
    LBrace,
    RBrace,
    Semi,
    Comma,
    Assign,
    EqEq,
    NotEq,
    Not,
    AndAnd,
    OrOr,
    Plus,
    Lt,
    Gt,
    Le,
    Ge,
    Eof,
}

fn tokenize(src: &str) -> Result<Vec<Tok>> {
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut toks = Vec::new();
    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '/' if chars.get(i + 1) == Some(&'/') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i = (i + 2).min(chars.len());
            }
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            '{' => {
                toks.push(Tok::LBrace);
                i += 1;
            }
            '}' => {
                toks.push(Tok::RBrace);
                i += 1;
            }
            ';' => {
                toks.push(Tok::Semi);
                i += 1;
            }
            ',' => {
                toks.push(Tok::Comma);
                i += 1;
            }
            '+' => {
                toks.push(Tok::Plus);
                i += 1;
            }
            '!' if chars.get(i + 1) == Some(&'=') => {
                toks.push(Tok::NotEq);
                i += 2;
            }
            '!' => {
                toks.push(Tok::Not);
                i += 1;
            }
            '=' if chars.get(i + 1) == Some(&'=') => {
                toks.push(Tok::EqEq);
                i += 2;
            }
            '=' => {
                toks.push(Tok::Assign);
                i += 1;
            }
            '&' if chars.get(i + 1) == Some(&'&') => {
                toks.push(Tok::AndAnd);
                i += 2;
            }
            '|' if chars.get(i + 1) == Some(&'|') => {
                toks.push(Tok::OrOr);
                i += 2;
            }
            '<' if chars.get(i + 1) == Some(&'=') => {
                toks.push(Tok::Le);
                i += 2;
            }
            '<' => {
                toks.push(Tok::Lt);
                i += 1;
            }
            '>' if chars.get(i + 1) == Some(&'=') => {
                toks.push(Tok::Ge);
                i += 2;
            }
            '>' => {
                toks.push(Tok::Gt);
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut s = String::new();
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                        s.push(match chars[i] {
                            'n' => '\n',
                            't' => '\t',
                            other => other,
                        });
                    } else {
                        s.push(chars[i]);
                    }
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(NetworkError::Parse(
                        "unterminated string in PAC script".into(),
                    ));
                }
                i += 1; // closing quote
                toks.push(Tok::Str(s));
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                let text: String = chars[start..i].iter().collect();
                let n = text
                    .parse()
                    .map_err(|_| NetworkError::Parse(format!("bad number literal '{text}'")))?;
                toks.push(Tok::Num(n));
            }
            c if c.is_alphabetic() || c == '_' || c == '$' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '$')
                {
                    i += 1;
                }
                toks.push(Tok::Ident(chars[start..i].iter().collect()));
            }
            other => {
                return Err(NetworkError::Parse(format!(
                    "unexpected character '{other}' in PAC script"
                )));
            }
        }
    }
    toks.push(Tok::Eof);
    Ok(toks)
}

// ---- AST ----------------------------------------------------------------

#[derive(Debug, Clone)]
enum Expr {
    Str(String),
    Num(f64),
    Bool(bool),
    Ident(String),
    Call(String, Vec<Expr>),
    Add(Box<Expr>, Box<Expr>),
    Eq(Box<Expr>, Box<Expr>),
    NotEq(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Lt(Box<Expr>, Box<Expr>),
    Gt(Box<Expr>, Box<Expr>),
    Le(Box<Expr>, Box<Expr>),
    Ge(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

#[derive(Debug, Clone)]
enum Stmt {
    VarDecl(String, Option<Expr>),
    Assign(String, Expr),
    ExprStmt(Expr),
    If(Expr, Vec<Stmt>, Vec<Stmt>),
    Return(Option<Expr>),
}

#[derive(Debug, Clone)]
struct FunctionDecl {
    params: Vec<String>,
    body: Vec<Stmt>,
}

/// A parsed PAC script: every top-level `function` declaration, plus
/// any top-level `var` statements to seed the global scope with
/// before calling `FindProxyForURL`.
struct Program {
    functions: HashMap<String, FunctionDecl>,
    globals: Vec<Stmt>,
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.pos]
    }
    fn advance(&mut self) -> Tok {
        let t = self.toks[self.pos].clone();
        if self.pos + 1 < self.toks.len() {
            self.pos += 1;
        }
        t
    }
    fn expect(&mut self, want: &Tok) -> Result<()> {
        if self.peek() == want {
            self.advance();
            Ok(())
        } else {
            Err(NetworkError::Parse(format!(
                "expected {want:?}, found {:?} in PAC script",
                self.peek()
            )))
        }
    }
    fn expect_ident(&mut self) -> Result<String> {
        match self.advance() {
            Tok::Ident(s) => Ok(s),
            other => Err(NetworkError::Parse(format!(
                "expected identifier, found {other:?} in PAC script"
            ))),
        }
    }

    fn parse_program(&mut self) -> Result<Program> {
        let mut functions = HashMap::new();
        let mut globals = Vec::new();
        while *self.peek() != Tok::Eof {
            match self.peek().clone() {
                Tok::Ident(kw) if kw == "function" => {
                    self.advance();
                    let name = self.expect_ident()?;
                    self.expect(&Tok::LParen)?;
                    let mut params = Vec::new();
                    if *self.peek() != Tok::RParen {
                        loop {
                            params.push(self.expect_ident()?);
                            if *self.peek() == Tok::Comma {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                    }
                    self.expect(&Tok::RParen)?;
                    let body = self.parse_block()?;
                    functions.insert(name, FunctionDecl { params, body });
                }
                _ => globals.push(self.parse_stmt()?),
            }
        }
        Ok(Program { functions, globals })
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>> {
        self.expect(&Tok::LBrace)?;
        let mut stmts = Vec::new();
        while *self.peek() != Tok::RBrace {
            if *self.peek() == Tok::Eof {
                return Err(NetworkError::Parse(
                    "unexpected end of PAC script (unclosed block)".into(),
                ));
            }
            stmts.push(self.parse_stmt()?);
        }
        self.expect(&Tok::RBrace)?;
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt> {
        match self.peek().clone() {
            Tok::Ident(kw) if kw == "var" => {
                self.advance();
                let name = self.expect_ident()?;
                let init = if *self.peek() == Tok::Assign {
                    self.advance();
                    Some(self.parse_expr()?)
                } else {
                    None
                };
                self.skip_semi();
                Ok(Stmt::VarDecl(name, init))
            }
            Tok::Ident(kw) if kw == "return" => {
                self.advance();
                let value = if *self.peek() == Tok::Semi || *self.peek() == Tok::RBrace {
                    None
                } else {
                    Some(self.parse_expr()?)
                };
                self.skip_semi();
                Ok(Stmt::Return(value))
            }
            Tok::Ident(kw) if kw == "if" => {
                self.advance();
                self.expect(&Tok::LParen)?;
                let cond = self.parse_expr()?;
                self.expect(&Tok::RParen)?;
                let then_branch = self.parse_block()?;
                let else_branch = if let Tok::Ident(kw2) = self.peek().clone() {
                    if kw2 == "else" {
                        self.advance();
                        if let Tok::Ident(kw3) = self.peek().clone() {
                            if kw3 == "if" {
                                vec![self.parse_stmt()?]
                            } else {
                                self.parse_block()?
                            }
                        } else {
                            self.parse_block()?
                        }
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                Ok(Stmt::If(cond, then_branch, else_branch))
            }
            Tok::Ident(name) => {
                // Either `name(...)` as a call statement (`alert(...)`)
                // or `name = expr` as an assignment; both start with an
                // identifier, so look ahead one token to tell them
                // apart.
                if self.toks.get(self.pos + 1) == Some(&Tok::Assign) {
                    self.advance();
                    self.advance(); // '='
                    let value = self.parse_expr()?;
                    self.skip_semi();
                    Ok(Stmt::Assign(name, value))
                } else {
                    let e = self.parse_expr()?;
                    self.skip_semi();
                    Ok(Stmt::ExprStmt(e))
                }
            }
            other => Err(NetworkError::Parse(format!(
                "unexpected token {other:?} in PAC script"
            ))),
        }
    }

    fn skip_semi(&mut self) {
        if *self.peek() == Tok::Semi {
            self.advance();
        }
    }

    // Precedence, low to high: || , && , equality , relational , additive , unary/primary.
    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_or()
    }
    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        while *self.peek() == Tok::OrOr {
            self.advance();
            left = Expr::Or(Box::new(left), Box::new(self.parse_and()?));
        }
        Ok(left)
    }
    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_equality()?;
        while *self.peek() == Tok::AndAnd {
            self.advance();
            left = Expr::And(Box::new(left), Box::new(self.parse_equality()?));
        }
        Ok(left)
    }
    fn parse_equality(&mut self) -> Result<Expr> {
        let mut left = self.parse_relational()?;
        loop {
            match self.peek() {
                Tok::EqEq => {
                    self.advance();
                    left = Expr::Eq(Box::new(left), Box::new(self.parse_relational()?));
                }
                Tok::NotEq => {
                    self.advance();
                    left = Expr::NotEq(Box::new(left), Box::new(self.parse_relational()?));
                }
                _ => break,
            }
        }
        Ok(left)
    }
    fn parse_relational(&mut self) -> Result<Expr> {
        let mut left = self.parse_additive()?;
        loop {
            match self.peek() {
                Tok::Lt => {
                    self.advance();
                    left = Expr::Lt(Box::new(left), Box::new(self.parse_additive()?));
                }
                Tok::Gt => {
                    self.advance();
                    left = Expr::Gt(Box::new(left), Box::new(self.parse_additive()?));
                }
                Tok::Le => {
                    self.advance();
                    left = Expr::Le(Box::new(left), Box::new(self.parse_additive()?));
                }
                Tok::Ge => {
                    self.advance();
                    left = Expr::Ge(Box::new(left), Box::new(self.parse_additive()?));
                }
                _ => break,
            }
        }
        Ok(left)
    }
    fn parse_additive(&mut self) -> Result<Expr> {
        let mut left = self.parse_unary()?;
        while *self.peek() == Tok::Plus {
            self.advance();
            left = Expr::Add(Box::new(left), Box::new(self.parse_unary()?));
        }
        Ok(left)
    }
    fn parse_unary(&mut self) -> Result<Expr> {
        if *self.peek() == Tok::Not {
            self.advance();
            return Ok(Expr::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }
    fn parse_primary(&mut self) -> Result<Expr> {
        match self.advance() {
            Tok::Str(s) => Ok(Expr::Str(s)),
            Tok::Num(n) => Ok(Expr::Num(n)),
            Tok::LParen => {
                let e = self.parse_expr()?;
                self.expect(&Tok::RParen)?;
                Ok(e)
            }
            Tok::Ident(name) => {
                if name == "true" {
                    return Ok(Expr::Bool(true));
                }
                if name == "false" {
                    return Ok(Expr::Bool(false));
                }
                if *self.peek() == Tok::LParen {
                    self.advance();
                    let mut args = Vec::new();
                    if *self.peek() != Tok::RParen {
                        loop {
                            args.push(self.parse_expr()?);
                            if *self.peek() == Tok::Comma {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                    }
                    self.expect(&Tok::RParen)?;
                    Ok(Expr::Call(name, args))
                } else {
                    Ok(Expr::Ident(name))
                }
            }
            other => Err(NetworkError::Parse(format!(
                "unexpected token {other:?} in PAC expression"
            ))),
        }
    }
}

fn parse(src: &str) -> Result<Program> {
    let toks = tokenize(src)?;
    Parser { toks, pos: 0 }.parse_program()
}

// ---- Interpreter ----------------------------------------------------------

enum Signal {
    None,
    Return(Value),
}

struct Interp<'a> {
    functions: &'a HashMap<String, FunctionDecl>,
}

impl<'a> Interp<'a> {
    fn call(&self, name: &str, args: Vec<Value>, depth: usize) -> Result<Value> {
        if depth > MAX_CALL_DEPTH {
            return Err(NetworkError::Other("PAC script recursion too deep".into()));
        }
        if let Some(v) = call_builtin(name, &args)? {
            return Ok(v);
        }
        let func = self.functions.get(name).ok_or_else(|| {
            NetworkError::Other(format!("PAC script calls undefined function '{name}'"))
        })?;
        let mut scope: HashMap<String, Value> = HashMap::new();
        for (param, arg) in func.params.iter().zip(args.into_iter()) {
            scope.insert(param.clone(), arg);
        }
        match self.exec_block(&func.body, &mut scope, depth + 1)? {
            Signal::Return(v) => Ok(v),
            Signal::None => Ok(Value::Null),
        }
    }

    fn exec_block(
        &self,
        stmts: &[Stmt],
        scope: &mut HashMap<String, Value>,
        depth: usize,
    ) -> Result<Signal> {
        for stmt in stmts {
            match self.exec_stmt(stmt, scope, depth)? {
                Signal::None => {}
                sig @ Signal::Return(_) => return Ok(sig),
            }
        }
        Ok(Signal::None)
    }

    fn exec_stmt(
        &self,
        stmt: &Stmt,
        scope: &mut HashMap<String, Value>,
        depth: usize,
    ) -> Result<Signal> {
        match stmt {
            Stmt::VarDecl(name, init) => {
                let v = match init {
                    Some(e) => self.eval(e, scope, depth)?,
                    None => Value::Null,
                };
                scope.insert(name.clone(), v);
                Ok(Signal::None)
            }
            Stmt::Assign(name, expr) => {
                let v = self.eval(expr, scope, depth)?;
                scope.insert(name.clone(), v);
                Ok(Signal::None)
            }
            Stmt::ExprStmt(e) => {
                self.eval(e, scope, depth)?;
                Ok(Signal::None)
            }
            Stmt::If(cond, then_b, else_b) => {
                if self.eval(cond, scope, depth)?.truthy() {
                    self.exec_block(then_b, scope, depth)
                } else {
                    self.exec_block(else_b, scope, depth)
                }
            }
            Stmt::Return(e) => {
                let v = match e {
                    Some(e) => self.eval(e, scope, depth)?,
                    None => Value::Null,
                };
                Ok(Signal::Return(v))
            }
        }
    }

    fn eval(&self, expr: &Expr, scope: &mut HashMap<String, Value>, depth: usize) -> Result<Value> {
        Ok(match expr {
            Expr::Str(s) => Value::Str(s.clone()),
            Expr::Num(n) => Value::Num(*n),
            Expr::Bool(b) => Value::Bool(*b),
            Expr::Ident(name) => scope.get(name).cloned().unwrap_or(Value::Null),
            Expr::Call(name, arg_exprs) => {
                let mut args = Vec::with_capacity(arg_exprs.len());
                for a in arg_exprs {
                    args.push(self.eval(a, scope, depth)?);
                }
                self.call(name, args, depth)?
            }
            Expr::Add(l, r) => {
                let (l, r) = (self.eval(l, scope, depth)?, self.eval(r, scope, depth)?);
                match (&l, &r) {
                    (Value::Num(a), Value::Num(b)) => Value::Num(a + b),
                    _ => Value::Str(format!("{}{}", l.as_string(), r.as_string())),
                }
            }
            Expr::Eq(l, r) => Value::Bool(values_eq(
                &self.eval(l, scope, depth)?,
                &self.eval(r, scope, depth)?,
            )),
            Expr::NotEq(l, r) => Value::Bool(!values_eq(
                &self.eval(l, scope, depth)?,
                &self.eval(r, scope, depth)?,
            )),
            Expr::And(l, r) => {
                let lv = self.eval(l, scope, depth)?;
                if !lv.truthy() {
                    lv
                } else {
                    self.eval(r, scope, depth)?
                }
            }
            Expr::Or(l, r) => {
                let lv = self.eval(l, scope, depth)?;
                if lv.truthy() {
                    lv
                } else {
                    self.eval(r, scope, depth)?
                }
            }
            Expr::Lt(l, r) => Value::Bool(
                self.eval(l, scope, depth)?.as_num() < self.eval(r, scope, depth)?.as_num(),
            ),
            Expr::Gt(l, r) => Value::Bool(
                self.eval(l, scope, depth)?.as_num() > self.eval(r, scope, depth)?.as_num(),
            ),
            Expr::Le(l, r) => Value::Bool(
                self.eval(l, scope, depth)?.as_num() <= self.eval(r, scope, depth)?.as_num(),
            ),
            Expr::Ge(l, r) => Value::Bool(
                self.eval(l, scope, depth)?.as_num() >= self.eval(r, scope, depth)?.as_num(),
            ),
            Expr::Not(e) => Value::Bool(!self.eval(e, scope, depth)?.truthy()),
        })
    }
}

fn values_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Num(x), Value::Num(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Null, Value::Null) => true,
        _ => a.as_string() == b.as_string(),
    }
}

/// Parses and runs `script`'s `FindProxyForURL(url, host)`, returning
/// its result verbatim (e.g. `"PROXY proxy.example.com:8080; DIRECT"`)
/// -- callers apply the same "first entry that works" semantics a
/// browser would, this just produces the string.
pub fn evaluate(script: &str, url: &str, host: &str) -> Result<String> {
    let program = parse(script)?;
    if !program.functions.contains_key("FindProxyForURL") {
        return Err(NetworkError::Other(
            "PAC script has no FindProxyForURL function".into(),
        ));
    }
    let mut globals: HashMap<String, Value> = HashMap::new();
    let interp = Interp {
        functions: &program.functions,
    };
    for stmt in &program.globals {
        interp.exec_stmt(stmt, &mut globals, 0)?;
    }
    let result = interp.call(
        "FindProxyForURL",
        vec![Value::Str(url.to_string()), Value::Str(host.to_string())],
        0,
    )?;
    match result {
        Value::Str(s) => Ok(s),
        Value::Null => Ok("DIRECT".to_string()),
        other => Ok(other.as_string()),
    }
}

// ---- Built-in PAC helper functions --------------------------------------

fn arg_str(args: &[Value], i: usize) -> Result<String> {
    args.get(i)
        .map(Value::as_string)
        .ok_or_else(|| NetworkError::Other(format!("PAC builtin missing argument {i}")))
}

fn resolve_host(host: &str) -> Option<String> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    let addrs: Vec<std::net::IpAddr> = (host, 0u16)
        .to_socket_addrs()
        .ok()?
        .map(|a| a.ip())
        .collect();
    addrs
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| addrs.first())
        .map(|ip| ip.to_string())
}

/// The kernel's own outbound-route choice for some address outside
/// any local subnet -- the standard portable way to ask "what's my
/// primary IP" without enumerating interfaces. No packet is actually
/// sent: UDP `connect()` only resolves a local route/source address,
/// which is exactly why a documentation-only address (RFC 5737
/// TEST-NET-3) is fine to use here as the nominal target.
fn my_ip_address() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|sock| {
            sock.connect(("203.0.113.1", 80))?;
            sock.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn is_in_net(ip: &str, pattern: &str, mask: &str) -> bool {
    let (Ok(ip), Ok(pattern), Ok(mask)) = (
        ip.parse::<std::net::Ipv4Addr>(),
        pattern.parse::<std::net::Ipv4Addr>(),
        mask.parse::<std::net::Ipv4Addr>(),
    ) else {
        return false;
    };
    (u32::from(ip) & u32::from(mask)) == (u32::from(pattern) & u32::from(mask))
}

fn sh_exp_match(s: &str, pattern: &str) -> bool {
    fn matches(s: &[u8], p: &[u8]) -> bool {
        match (s.first(), p.first()) {
            (_, Some(b'*')) => matches(s, &p[1..]) || (!s.is_empty() && matches(&s[1..], p)),
            (Some(_), Some(b'?')) => matches(&s[1..], &p[1..]),
            (Some(sc), Some(pc)) if sc == pc => matches(&s[1..], &p[1..]),
            (None, None) => true,
            _ => false,
        }
    }
    matches(s.as_bytes(), pattern.as_bytes())
}

fn now_unix_days_and_secs() -> (i64, u32) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    (secs.div_euclid(86400), secs.rem_euclid(86400) as u32)
}

/// Howard Hinnant's `civil_from_days` -- days-since-epoch to
/// proleptic-Gregorian (year, month, day). Public-domain algorithm,
/// small enough to inline rather than pull in a date/calendar crate
/// for the three PAC functions that need it.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn weekday_from_days(z: i64) -> u32 {
    // 1970-01-01 (z=0) was a Thursday; Sunday = 0.
    (z.rem_euclid(7) + 4).rem_euclid(7) as u32
}

const WEEKDAYS: &[&str] = &["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

fn weekday_range(args: &[Value]) -> Result<bool> {
    let (days, _) = now_unix_days_and_secs();
    let today = weekday_from_days(days);
    let idx = |s: &str| WEEKDAYS.iter().position(|w| *w == s.to_ascii_uppercase());
    let d1 = args.first().map(Value::as_string).and_then(|s| idx(&s));
    let Some(d1) = d1 else { return Ok(false) };
    match args.get(1).map(Value::as_string).and_then(|s| idx(&s)) {
        None => Ok(today == d1 as u32),
        Some(d2) => {
            let (d1, d2) = (d1 as u32, d2 as u32);
            if d1 <= d2 {
                Ok(today >= d1 && today <= d2)
            } else {
                Ok(today >= d1 || today <= d2)
            }
        }
    }
}

fn date_range(args: &[Value]) -> Result<bool> {
    let (days, _) = now_unix_days_and_secs();
    let (_, _, today) = civil_from_days(days);
    let d1 = args.first().map(|v| v.as_num() as u32);
    let Some(d1) = d1 else { return Ok(false) };
    match args.get(1).map(|v| v.as_num() as u32) {
        None => Ok(today == d1),
        Some(d2) => {
            if d1 <= d2 {
                Ok(today >= d1 && today <= d2)
            } else {
                Ok(today >= d1 || today <= d2)
            }
        }
    }
}

fn time_range(args: &[Value]) -> Result<bool> {
    let (_, secs) = now_unix_days_and_secs();
    let hour = secs / 3600;
    let h1 = args.first().map(|v| v.as_num() as u32);
    let Some(h1) = h1 else { return Ok(false) };
    match args.get(1).map(|v| v.as_num() as u32) {
        None => Ok(hour == h1),
        Some(h2) => {
            if h1 <= h2 {
                Ok(hour >= h1 && hour <= h2)
            } else {
                Ok(hour >= h1 || hour <= h2)
            }
        }
    }
}

fn call_builtin(name: &str, args: &[Value]) -> Result<Option<Value>> {
    Ok(Some(match name {
        "isPlainHostName" => Value::Bool(!arg_str(args, 0)?.contains('.')),
        "dnsDomainIs" => {
            let host = arg_str(args, 0)?.to_ascii_lowercase();
            let domain = arg_str(args, 1)?.to_ascii_lowercase();
            Value::Bool(host.ends_with(&domain))
        }
        "localHostOrDomainIs" => {
            let host = arg_str(args, 0)?.to_ascii_lowercase();
            let hostdom = arg_str(args, 1)?.to_ascii_lowercase();
            Value::Bool(
                host == hostdom
                    || (!host.contains('.') && hostdom.starts_with(&format!("{host}."))),
            )
        }
        "isResolvable" => Value::Bool(resolve_host(&arg_str(args, 0)?).is_some()),
        "dnsResolve" => resolve_host(&arg_str(args, 0)?)
            .map(Value::Str)
            .unwrap_or(Value::Null),
        "myIpAddress" => Value::Str(my_ip_address()),
        "dnsDomainLevels" => Value::Num(arg_str(args, 0)?.matches('.').count() as f64),
        "isInNet" => {
            let host = arg_str(args, 0)?;
            let pattern = arg_str(args, 1)?;
            let mask = arg_str(args, 2)?;
            match resolve_host(&host) {
                Some(ip) => Value::Bool(is_in_net(&ip, &pattern, &mask)),
                None => Value::Bool(false),
            }
        }
        "shExpMatch" => Value::Bool(sh_exp_match(&arg_str(args, 0)?, &arg_str(args, 1)?)),
        "weekdayRange" => Value::Bool(weekday_range(args)?),
        "dateRange" => Value::Bool(date_range(args)?),
        "timeRange" => Value::Bool(time_range(args)?),
        "alert" => Value::Null,
        _ => return Ok(None),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_direct_script() {
        let script = r#"
            function FindProxyForURL(url, host) {
                return "DIRECT";
            }
        "#;
        assert_eq!(
            evaluate(script, "http://example.com/", "example.com").unwrap(),
            "DIRECT"
        );
    }

    #[test]
    fn plain_hostname_goes_direct_else_proxy() {
        let script = r#"
            function FindProxyForURL(url, host) {
                if (isPlainHostName(host)) {
                    return "DIRECT";
                }
                return "PROXY proxy.example.com:8080; DIRECT";
            }
        "#;
        assert_eq!(
            evaluate(script, "http://fileserver/", "fileserver").unwrap(),
            "DIRECT"
        );
        assert_eq!(
            evaluate(script, "http://example.com/", "example.com").unwrap(),
            "PROXY proxy.example.com:8080; DIRECT"
        );
    }

    #[test]
    fn dns_domain_is_and_shexpmatch() {
        let script = r#"
            function FindProxyForURL(url, host) {
                if (dnsDomainIs(host, ".internal.example.com")) {
                    return "DIRECT";
                }
                if (shExpMatch(host, "*.cdn.example.com")) {
                    return "PROXY cdn-proxy:8080";
                }
                return "PROXY proxy.example.com:8080";
            }
        "#;
        assert_eq!(
            evaluate(script, "x", "app.internal.example.com").unwrap(),
            "DIRECT"
        );
        assert_eq!(
            evaluate(script, "x", "assets.cdn.example.com").unwrap(),
            "PROXY cdn-proxy:8080"
        );
        assert_eq!(
            evaluate(script, "x", "example.org").unwrap(),
            "PROXY proxy.example.com:8080"
        );
    }

    #[test]
    fn helper_functions_and_variables() {
        let script = r#"
            var backup = "PROXY backup.example.com:8080";
            function isInternal(host) {
                return dnsDomainIs(host, ".corp.example.com");
            }
            function FindProxyForURL(url, host) {
                if (isInternal(host)) {
                    return "DIRECT";
                }
                return backup;
            }
        "#;
        assert_eq!(
            evaluate(script, "x", "db.corp.example.com").unwrap(),
            "DIRECT"
        );
        assert_eq!(
            evaluate(script, "x", "example.com").unwrap(),
            "PROXY backup.example.com:8080"
        );
    }

    #[test]
    fn recursion_is_bounded() {
        let script = r#"
            function loop(n) {
                return loop(n + 1);
            }
            function FindProxyForURL(url, host) {
                return loop(0);
            }
        "#;
        assert!(evaluate(script, "x", "y").is_err());
    }

    #[test]
    fn sh_exp_match_wildcards() {
        assert!(sh_exp_match("foo.example.com", "*.example.com"));
        assert!(sh_exp_match("example.com", "example.com"));
        assert!(!sh_exp_match("example.com", "*.example.com"));
        assert!(sh_exp_match("abc", "a?c"));
    }

    #[test]
    fn is_in_net_matches_subnet() {
        assert!(is_in_net("10.1.2.3", "10.0.0.0", "255.0.0.0"));
        assert!(!is_in_net("11.1.2.3", "10.0.0.0", "255.0.0.0"));
    }

    #[test]
    fn dechunk_reassembles_chunks() {
        let chunked = "5\r\nHello\r\n6\r\n, PAC!\r\n0\r\n\r\n";
        assert_eq!(dechunk(chunked), "Hello, PAC!");
    }
}
