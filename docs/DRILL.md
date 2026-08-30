# The warden-connect Rust Drill

> A build ladder that ships [docs/08-lld.md](08-lld.md) and teaches Rust at
> the same time. Fourteen sessions, one module per sitting, each one a committed
> unit with tests green.
>
> Calibrated for: *some Rust, hit walls on lifetimes / traits / error types /
> structuring past one file.* Every session names the wall it is there to break.

---

## 1 · How we work

| | |
|---|---|
| **I write** | The module — types, functions, tests — and then explain it function by function: what it does, the Rust mechanics in play, and which alternatives I rejected and why. |
| **You read and interrogate** | Push on anything that isn't obvious. "Why not `&str` there", "what breaks if you drop that bound", "why isn't this an enum". The questions are the learning. |
| **You then own it** | Refactor, rename, disagree. If you'd have written it differently, say so — sometimes you'll be right, and either way you'll know why the code is the shape it is. |
| **Every module ends with** | A grip check (3 questions, from memory) and a mutation drill (I break one line, you diagnose from the compiler error alone). |

**The honest trade:** this format gets to working code fastest and builds grip
more slowly than writing it yourself would. The grip check and the mutation drill
are what stop it from becoming passive reading — they're the part that tells us
whether it actually landed. If a grip check goes badly, that module gets
re-explained, not waved through.

---

## 2 · House rules for the code

These are the standing conventions; I'll stop reminding you after session 3.

1. **No `unwrap()` or `expect()` outside `#[cfg(test)]`.** Enforced by clippy in
   `Cargo.toml`. In tests, `unwrap()` is fine and idiomatic.
2. **`Result<T>` everywhere a thing can fail**, with a `WcError` carrying a
   `WC-*` code. No `Option` to mean failure, no sentinel values, no panics on
   bad input — panics are for broken *invariants*, never for bad *data*.
3. **Every `pub` item gets a doc comment** saying what it does and what it
   promises. `#![warn(missing_docs)]` will nag you. The nag is the lesson.
4. **Borrow before you clone.** When you reach for `.clone()`, say out loud why
   the borrow wouldn't work. Half the time you'll discover it would.
5. **`cargo fmt` before every review**, `cargo clippy -- -D warnings` clean
   before every commit.
6. **Tests are part of the module, not homework.** A session isn't done when it
   compiles; it's done when its tests pass and clippy is quiet.
7. **Match the surrounding code.** We're extending Warden core's idiom
   (`Result<T, String>` at its edges, `pub fn` verbs, `//!` module docs) — not
   importing a new house style.

---

## 3 · The ladder

Order is forced by two things: what compiles without the rest of the tree, and
which wall you need broken before the next module is even readable.

| # | Module | Rust you'll actually learn | The wall it breaks |
|---|---|---|---|
| **1** | `wc-core::error` | Newtype pattern · `const` items · `static` tables · `Display`/`Error` traits · `FromStr` · `Box<dyn Error>` · `Option` · exhaustive `match` · type aliases | **Error handling at scale.** Why `Box<dyn Error>` isn't a design, and how a real error type carries a code, a source, and a fail direction. |
| **2** | `wc-core::model` — ids | Newtypes over `String` · validating constructors · `&str` vs `String` vs `impl Into<String>` · `TryFrom` · `AsRef<str>` · when *not* to `Deref` | **`&str` vs `String`.** The single most common Rust stall. You'll stop guessing and start knowing which one a signature wants. |
| **3** | `wc-core::model` — entities | `struct`/`enum` design · `serde` derive · `#[serde(rename_all)]` · `Option<T>` fields · `BTreeMap` vs `HashMap` · exhaustive state-machine `match` | **Making illegal states unrepresentable.** The lifecycle table from §8.5.1 becomes unreachable code, not a comment. |
| **4** | `wc-core::canon` — normalise | Iterators & adaptors (`chars`, `filter`, `map`, `collect`) · `char` vs `u8` vs grapheme · borrowing in loops · `Cow<str>` | **Iterator chains.** And the borrow checker's favourite trap: mutating what you're iterating. |
| **5** | `wc-core::canon` — project & order | Recursion over `serde_json::Value` · `match` on enums with data · `BTreeMap` ordering · ownership when transforming trees | **Recursive ownership.** Rebuilding a tree while owning parts of it. |
| **6** | `wc-core::canon` — pin | Traits & generics · `impl Trait` args · trait bounds · writing property tests · `#[cfg(test)]` modules | **Generics vs trait objects** — when each is the right tool. |
| **7** | `wc-control::store` — `Log<T>` | Generic structs with bounds · `where` clauses · `Serialize`/`DeserializeOwned` · `Drop` · file I/O · `unsafe` at the `libc` boundary (`flock`) | **Generic data structures.** Plus your first justified `unsafe` block, wrapped so callers never see it. |
| **8** | `wc-control::store` — `Projection` | `HashMap`/`HashSet` · the `entry` API · **borrow splitting** · `&mut self` methods returning references · iterator over map values | **The classic wall:** "cannot borrow `self` as mutable more than once". You'll learn the four standard escapes and when each is right. |
| **9** | `wc-control::registry` | Structs holding references · **explicit lifetimes** (`Registry<'a>`) · lifetime elision rules · returning `&T` vs `T` vs `Arc<T>` | **Lifetimes.** Not the theory — the three real cases where you must write `'a` and the many where you must not. |
| **10** | `wc-control::evidence` | Cross-crate deps · path dependencies · trait objects (`Box<dyn Sink>`) · adapting *someone else's* API (Warden core's `audit.rs`) · `From` conversions between error types | **Working inside an existing codebase.** Reuse without forking. |
| **11** | `wc-core::contract` | Third-party crates (`jsonwebtoken`, `serde_json`) · builder patterns · time handling · `Option` combinators (`map`/`and_then`/`ok_or`) · constant-time comparison | **Reading and driving unfamiliar crate APIs** from docs alone. |
| **12** | `wc-mediator::cache` | `Arc` · `RwLock` · copy-on-write snapshot swap · `Send`/`Sync` · atomics · interior mutability · why `Arc<Mutex<HashMap>>` is usually the wrong reflex | **Shared mutable state.** The thing that makes people give up on Rust concurrency. |
| **13** | `wc-mediator::gate` + `filter` | Ordering side effects · early return with `?` · slices & sets · writing an invariant as a property test · benchmarking | **Proving a security property** in code rather than asserting it in prose. |
| **14** | `wc-control::api` + `wc-cli` | Threads & `move` closures · `'static` bounds · `Arc<T>` across threads · CLI arg parsing without a framework · integration tests | **Wiring a binary together.** The last mile everyone skips. |

Sessions 1–6 are `wc-core` and need no dependencies at all — pure Rust, fastest
possible feedback loop. Sessions 7–14 open the P0 surface from §8.16.

---

## 4 · The per-session ritual

Same six steps every time. The last two are the ones that build grip.

1. **Brief** (me, ~5 min read) — the design decision behind the module and the
   Rust concepts in play.
2. **Write** (me) — the module and its tests, `cargo fmt` / `clippy -D warnings`
   / `cargo test` all clean before you read a line of it.
3. **Explain** (me) — function by function, grouped by concept. Not a line-by-line
   transcript: the *why*, and what the alternatives would have cost.
4. **Interrogate** (you) — anything unclear, anything you'd have done differently.
   We stay here as long as it takes; this is the actual session.
5. **Grip check** (you, from memory, no scrolling) — three questions about code
   *you just read*. If you can't answer, we haven't finished the session,
   regardless of whether the tests pass.
6. **Mutation drill** (me → you) — I break one line in your module and hand you
   the compiler error or failing test. You diagnose it without looking at the
   diff. This is the single highest-value five minutes in the whole ritual:
   reading Rust's errors fluently is most of what "knowing Rust" feels like
   day to day.

Then: `cargo fmt && cargo clippy -- -D warnings && cargo test`, commit, log it
in §6.

**Escalation rule.** If a concept doesn't land after two different
explanations, we stop explaining and shrink the hole — I'll split the function
into two smaller ones and you'll do the easy half first. Confusion that persists
is a sizing problem, not an intelligence problem.

---

## 5 · Session briefs

### Session 1 · `wc-core::error` — the code table

**Why this first.** Every other module returns `Result<T, WcError>`. Get the
error type wrong and you refactor 11 kLOC later. It's also the smallest module
that teaches four traits at once, and it has zero dependencies — pure Rust,
instant compile.

**The design decision, and the lesson in it.** The LLD says 69 codes, each
appearing in exactly one place. The obvious Rust answer is a 69-variant enum,
and it's wrong here:

| | 69-variant `enum` | Newtype `Code(u16)` + `static` table ← ours |
|---|---|---|
| Exhaustive `match` | yes — but we never want to match all 69 | no |
| `as_str()`, `http()`, `fail_direction()` | three 69-arm matches, ~210 lines of mechanical code | one table, three lookups |
| Adding a code | touch every match | one row |
| Numeric identity (`WC-3108`) | manual discriminants, easy to desync | *is* the representation |

So: `Code` is a validated newtype over `u16`, and the per-code facts live in one
sorted `static CODES` table. What we *do* want exhaustive matching on is the
small `Category` enum (9 variants) and `FailDirection` (4) — so those stay
enums. **The general lesson: reach for an enum when you want the compiler to
force you to handle every case; reach for a table when the cases are data.**

**Concepts you'll use** — read these before starting, they're each ~5 min:

| Concept | Where it shows up | Reference |
|---|---|---|
| Newtype pattern | `struct Code(u16)` | [Rust Book 19.3](https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#using-the-newtype-pattern-to-implement-external-traits-on-external-types) |
| `Display` vs `Debug` | `impl Display for Code` writing `WC-3108` | [std::fmt](https://doc.rust-lang.org/std/fmt/) |
| `std::error::Error` + `source()` | error chaining | [std::error::Error](https://doc.rust-lang.org/std/error/trait.Error.html) |
| `Box<dyn Error + Send + Sync>` | wrapping a cause you don't own | Book 18.2 |
| `FromStr` | `"WC-3108".parse::<Code>()` | [std::str::FromStr](https://doc.rust-lang.org/std/str/trait.FromStr.html) |
| `static` + `const` + slices | the `CODES` table, `binary_search_by_key` | [Book 3.1](https://doc.rust-lang.org/book/ch03-01-variables-and-mutability.html) |
| Match guards & ranges | `Category::of` | Book 18.3 |

**Your holes** (nine, in the order I'd do them):

| # | Item | What it teaches |
|---|---|---|
| 1 | `Code::new` | Validation at the boundary; `Result` over `Option` |
| 2 | `Category::of` | Range patterns, exhaustive return |
| 3 | `Code::spec` | `binary_search_by_key`, `Option`, `&'static` |
| 4 | `impl Display for Code` | `write!`, formatter width (`{:04}`) |
| 5 | `impl FromStr for Code` | Parsing, `strip_prefix`, error mapping |
| 6 | `Code::fail_direction` / `is_fail_closed` | Delegating through a lookup; exhaustive match on `FailDirection` |
| 7 | `WcError::new` / `with_detail` | `impl Into<String>` args — why not `&str`, why not `String` |
| 8 | `WcError::with_source` | Generic bounds `E: Error + Send + Sync + 'static`, boxing |
| 9 | `impl Display` + `impl Error for WcError` | The two traits that make an error type *an error type* |

Stretch (optional, only if you're enjoying it): `macro_rules! wc_bail` so
`wc_bail!(Code::PIN_MISMATCH, "presented {presented} != pinned {pinned}")`
works. Macros are where Rust stops looking like other languages.

**Grip-check questions** you'll answer at the end, so read the code with them in
mind:

1. Why does `WcError::with_source` need `+ Send + Sync + 'static`, and what
   breaks at a call site if you drop each of the three?
2. `Code::spec` returns `Option<&'static CodeSpec>`. Where does that reference
   live, and why is no lifetime annotation needed on the method?
3. Why is `detail: String` and not `&str`, given rule 4 says borrow before you
   clone?

---

### Sessions 2–14

Briefs are written at the start of each session, not up front — each one is
shaped by what the review of the previous session showed you'd already
internalised and what you hadn't. A curriculum written on day one is a
curriculum that ignores you.

---

## 6 · Progress log

Fill the last two columns in yourself; they're the honest record.

| # | Module | Committed | Grip check | What actually cost me time |
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

---

## 7 · Tooling

```sh
cargo fmt                            # before every review
cargo clippy --all-targets -- -D warnings
cargo test                           # whole workspace
cargo test -p warden-connect-core error::        # one module
cargo test -- --nocapture            # see your dbg!/println!
cargo doc --open                     # read your own docs as docs
```

Worth installing when we reach the session that needs it:

| Tool | Session | Why |
|---|---|---|
| `rustup component add rust-analyzer` | now, if your editor lacks it | inline types and errors — this alone will double your speed |
| `cargo install cargo-nextest` | 7 | much faster, clearer test output |
| `cargo install cargo-fuzz` | 6 | the `canon_surface` fuzz target from §8.15 |
| `cargo install cargo-expand` | 1 stretch | see what `macro_rules!` and `derive` actually generate |

Two habits worth forming now: read the **first** compiler error only and
recompile (later ones are usually fallout), and run `rustc --explain E0499` on
any error code you don't recognise.
