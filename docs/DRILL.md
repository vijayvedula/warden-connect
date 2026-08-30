# The warden-connect Rust Drill

A build ladder that ships [docs/08-lld.md](08-lld.md) and teaches Rust while
doing it. Fourteen sessions, one module each, every session a committed unit
with tests green.

Calibrated for someone with some Rust who stalls on lifetimes, traits, error
types and structuring past one file. Each session names the wall it breaks.

## 1 · How we work

| Step | Who |
|---|---|
| Write the module — types, functions, tests | me |
| Explain it function by function: what it does, the Rust in play, the alternatives rejected | me |
| Interrogate anything unclear or anything you would have done differently | you |
| Grip check: three questions from memory, no scrolling | you |
| Mutation drill: I break one line, you diagnose from the compiler error alone | you |

This reaches working code faster than writing it yourself, and builds grip more
slowly. The grip check and mutation drill are what test whether it landed. A bad
grip check means the module is re-explained, not waved through.

## 2 · House rules

| # | Rule |
|---|---|
| 1 | No `unwrap()` or `expect()` outside `#[cfg(test)]`. Enforced by clippy in `Cargo.toml` |
| 2 | `Result<T>` wherever something can fail, carrying a `WcError` with a `WC-*` code. Panics are for broken invariants, never for bad data |
| 3 | Every `pub` item gets a doc comment. `#![warn(missing_docs)]` enforces it |
| 4 | Borrow before you clone. When reaching for `.clone()`, say why the borrow will not work |
| 5 | `cargo fmt` before every review; `cargo clippy -- -D warnings` clean before every commit |
| 6 | Tests are part of the module. A session is done when its tests pass and clippy is quiet |
| 7 | Match the surrounding code. Extend Warden core's idiom rather than importing a new one |

## 3 · The ladder

Order is forced by what compiles without the rest of the tree, and by which wall
must break before the next module is readable.

| # | Module | Rust it teaches | Wall it breaks |
|---|---|---|---|
| 1 | `wc-core::error` | Newtype · `const`/`static` tables · `Display`/`Error` · `FromStr` · `Box<dyn Error>` · exhaustive `match` | Error handling at scale |
| 2 | `wc-core::model` — ids | Newtypes over `String` · validating constructors · `&str` vs `String` vs `impl Into<String>` · `TryFrom` · `AsRef<str>` | `&str` vs `String` |
| 3 | `wc-core::model` — entities | `struct`/`enum` design · `serde` derive · `Option<T>` fields · `BTreeMap` vs `HashMap` | Making illegal states unrepresentable |
| 4 | `wc-core::canon` — normalise | Iterators and adaptors · `char` vs `u8` vs grapheme · borrowing in loops · `Cow<str>` | Iterator chains, and mutating what you iterate |
| 5 | `wc-core::canon` — project & order | Recursion over `serde_json::Value` · `match` on enums with data · `BTreeMap` ordering | Recursive ownership |
| 6 | `wc-core::canon` — pin | Traits and generics · `impl Trait` args · trait bounds · property tests | Generics vs trait objects |
| 7 | `wc-control::store` — `Log<T>` | Generic structs with bounds · `where` clauses · `Serialize`/`DeserializeOwned` · `Drop` · file I/O · `unsafe` at the `libc` boundary | Generic data structures, and a justified `unsafe` block |
| 8 | `wc-control::store` — `Projection` | `HashMap`/`HashSet` · the `entry` API · borrow splitting · `&mut self` returning references | "cannot borrow `self` as mutable more than once" |
| 9 | `wc-control::registry` | Structs holding references · explicit lifetimes · elision rules · `&T` vs `T` vs `Arc<T>` | Lifetimes |
| 10 | `wc-control::evidence` | Cross-crate deps · path dependencies · `Box<dyn Sink>` · adapting someone else's API · `From` conversions | Working inside an existing codebase |
| 11 | `wc-core::contract` | Third-party crates · builder patterns · time handling · `Option` combinators · constant-time comparison | Driving unfamiliar crate APIs from docs |
| 12 | `wc-mediator::cache` | `Arc` · `RwLock` · copy-on-write snapshot swap · `Send`/`Sync` · atomics · interior mutability | Shared mutable state |
| 13 | `wc-mediator::gate` + `filter` | Ordering side effects · early return with `?` · slices and sets · invariants as property tests | Proving a security property in code |
| 14 | `wc-control::api` + `wc-cli` | Threads and `move` closures · `'static` bounds · `Arc<T>` across threads · CLI parsing without a framework | Wiring a binary together |

Sessions 1–6 are `wc-core` and need no dependencies. Sessions 7–14 open the P0
surface from [§8.16](08-lld.md).

## 4 · Per-session ritual

| # | Step | Notes |
|---|---|---|
| 1 | Brief | The design decision and the Rust concepts in play |
| 2 | Write | Module and tests, with fmt, clippy and test clean before you read a line |
| 3 | Explain | Function by function, grouped by concept: the why, and what the alternatives cost |
| 4 | Interrogate | As long as it takes. This is the session |
| 5 | Grip check | Three questions from memory. Failing it means the session is not finished |
| 6 | Mutation drill | One broken line, diagnosed from the compiler error without the diff |

Then `cargo fmt && cargo clippy -- -D warnings && cargo test`, commit, log in §6.

If a concept does not land after two explanations, the function gets split and
you take the easier half first. Persistent confusion is a sizing problem.

## 5 · Session 1 · `wc-core::error`

Every other module returns `Result<T, WcError>`, so the error type comes first.
It is also the smallest module that exercises four traits and has no
dependencies.

**The design decision.** There are 82 codes, each appearing in one place. A
82-variant enum is the obvious answer and the wrong one:

| | 82-variant `enum` | Newtype `Code(u16)` + `static` table ← ours |
|---|---|---|
| Exhaustive `match` | yes, but matching all 82 is never wanted | no |
| `as_str()`, `http()`, `fail_direction()` | three 82-arm matches | one table, three lookups |
| Adding a code | touch every match | one row |
| Numeric identity (`WC-3108`) | manual discriminants, easy to desync | is the representation |

`Code` is a validated newtype over `u16` and the per-code facts live in one
sorted `static` table. `Category` (9 variants) and `FailDirection` (4) stay
enums, because exhaustive matching on those is wanted. Use an enum when the
compiler should force every case; use a table when the cases are data.

**Concepts to read first**

| Concept | Where it shows up |
|---|---|
| Newtype pattern | `struct Code(u16)` |
| `Display` vs `Debug` | `impl Display for Code` writing `WC-3108` |
| `std::error::Error` + `source()` | error chaining |
| `Box<dyn Error + Send + Sync>` | wrapping a cause you do not own |
| `FromStr` | `"WC-3108".parse::<Code>()` |
| `static`, `const`, slices | the `CODES` table and `binary_search_by_key` |
| Match guards and ranges | `Category::of` |

**Your holes**, in order

| # | Item | What it teaches |
|---|---|---|
| 1 | `Code::new` | Validation at the boundary; `Result` over `Option` |
| 2 | `Category::of` | Range patterns, exhaustive return |
| 3 | `Code::spec` | `binary_search_by_key`, `Option`, `&'static` |
| 4 | `impl Display for Code` | `write!`, formatter width (`{:04}`) |
| 5 | `impl FromStr for Code` | Parsing, `strip_prefix`, error mapping |
| 6 | `Code::fail_direction` / `is_fail_closed` | Delegating through a lookup; exhaustive match |
| 7 | `WcError::new` / `with_detail` | `impl Into<String>` args |
| 8 | `WcError::with_source` | Generic bounds `E: Error + Send + Sync + 'static`, boxing |
| 9 | `impl Display` + `impl Error for WcError` | The two traits that make an error type an error type |

Optional stretch: a `macro_rules! wc_bail` so
`wc_bail!(Code::PIN_MISMATCH, "presented {presented} != pinned {pinned}")` works.

**Grip-check questions**

1. Why does `WcError::with_source` need `+ Send + Sync + 'static`, and what breaks at a call site if you drop each?
2. `Code::spec` returns `Option<&'static CodeSpec>`. Where does that reference live, and why does the method need no lifetime annotation?
3. Why is `detail: String` and not `&str`, given rule 4?

## Sessions 2–14

Briefs are written at the start of each session rather than up front, shaped by
what the previous review showed had landed and what had not.

## 6 · Progress log

| # | Module | Committed | Grip check | What cost time |
|---|---|---|---|---|
| 1 | `wc-core::error` | | | |
| 2 | `wc-core::model` ids | | | |
| 3 | `wc-core::model` entities | | | |
| 4 | `wc-core::canon` normalise | | | |
| 5 | `wc-core::canon` project | | | |
| 6 | `wc-core::canon` pin | | | |
| 7 | `wc-control::store` `Log<T>` | | | |
| 8 | `wc-control::store` `Projection` | | | |
| 9 | `wc-control::registry` | | | |
| 10 | `wc-control::evidence` | | | |
| 11 | `wc-core::contract` | | | |
| 12 | `wc-mediator::cache` | | | |
| 13 | `wc-mediator::gate` + `filter` | | | |
| 14 | `wc-control::api` + `wc-cli` | | | |

## 7 · Tooling

```sh
cargo fmt                                         # before every review
cargo clippy --all-targets -- -D warnings
cargo test                                        # whole workspace
cargo test -p warden-connect-core error::         # one module
cargo test -- --nocapture                         # see dbg!/println!
cargo doc --open
```

| Tool | Session | Why |
|---|---|---|
| `rustup component add rust-analyzer` | now | inline types and errors |
| `cargo install cargo-nextest` | 7 | faster, clearer test output |
| `cargo install cargo-fuzz` | 6 | the `canon_surface` fuzz target from [§8.15](08-lld.md) |
| `cargo install cargo-expand` | 1 stretch | see what `macro_rules!` and `derive` generate |

Two habits: read the first compiler error only and recompile, and run
`rustc --explain E0499` on any error code you do not recognise.
