# Flying-Ace Engine ✈️
_Rhai-powered detection rules for Linux process events_


---

## ✨ What is this?

Flying-Ace is a **tiny rule-engine** that lets you write Sigma-style
detection rules in YAML, but express the logic itself in the
[Rhai scripting language](https://rhai.rs).
At runtime every incoming **Linux `process_creation` ECS event** is pushed
into a Rhai `Scope`; your rule’s `eval:` expression returns `true/false`.
If it’s `true`, the rule name is returned as a match.


---

## 🗜️ Event model in Rhai

| ECS field               | Accessible in Rhai as…                  |
|-------------------------|-----------------------------------------|
| `process.name`          | `process.name`                          |
| `process.executable`    | `process.executable`                    |
| `process.args` (string) | `process.args`                          |
| … _etc._                | see `ProcessEvent::to_scope()`          |

Primitive fields are plain strings/ints; nested ones are Rhai
`Map`s (just like JS objects).

---

## ✍️ Writing a rule

```yaml
# rules/linux/process_creation/curl_upload_file_regex.yaml
name: curl_upload_file_regex            # anything you like
eval: |
  // flag curl uploads of sensitive files via --upload-file
  process.name == "curl"
    && re_match(process.args, "(--upload-file\\s+)/(etc|passwd|shadow)")
````

*Put **one rule per file**; only two keys are read: `name:` and `eval:`.*

### String helpers available inside `eval`

| Function (all lowercase) | Signature                     | Purpose & example                              |
| ------------------------ | ----------------------------- | ---------------------------------------------- |
| `starts_with`            | `starts_with(string, list)`   | `starts_with(process.executable, ["/tmp/"])`   |
| `ends_with`              | `ends_with(string, list)`     | `ends_with(process.executable, ["bash","sh"])` |
| `contains`               | `contains(string, list)`      | `contains(process.args, ["-e","-c"])`          |
| `contains_all`           | `contains_all(string, list)`  | `contains_all(process.args, ["-e","bash"])`    |
| `matches`¹               | *alias for `re_match`*        | –                                              |
| `re_match` **(NEW)**     | `re_match(string, "<regex>")` | `re_match(process.args, "id -Gn [`'`]")`       |

> ¹ `matches` is provided by Rhai itself (same sig as `re_match` after we register it).

All helpers are case-sensitive (Rhai’s default).
List arguments may be a single string (`"bash"`) or `["bash","zsh"]`.

---

## 🧪 Running the tests

```bash
cargo test            # unit tests in src/
cargo test -- --nocapture
cargo test -p flying_ace_engine   # if used in workspace
```

The integration suite lives in **`tests/engine.rs`** and exercises every
sample rule.

---

## 🚀 Using in your project

```rust
use flying_ace_engine::{EcsRhaiEngine, ProcessEvent};

let engine = EcsRhaiEngine::new_from_dir("rules");

let event : ProcessEvent = /* deserialise JSON, etc. */ ;

let hits = engine.eval(&event);
if !hits.is_empty() {
    println!("ALERT! matched: {hits:?}");
}
```

