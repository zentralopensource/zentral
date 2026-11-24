---
title: ZQL grammar
weight: 307
---

ZQL is the Zentral query language for events. A query is a source, then stages separated by `|`:

```text
events
| where created_at > now() - 7d and type == "santa_event"
| where payload.decision == "BLOCK_UNKNOWN"
| stats count() as n by serial_number
| sort n desc
| limit 20
```

This page publishes the grammar of the language. No Zentral endpoint runs ZQL queries yet: the grammar is the first part, and the parts that check, authorize and run a query follow it.

The grammar is the file `zentral/core/zql/grammar.lark`. It is a [Lark](https://lark-parser.readthedocs.io/) grammar, and Zentral parses with it: the specification and the parser are the same file. The grammar at the end of this page is a copy of the file, and the documentation build fails if the copy and the file are different.

## Read the grammar

- A rule name starts with a lowercase letter. A terminal name (a token) is in uppercase.
- A quoted string, for example `"where"`, is a keyword or a punctuation mark.
- `?rule` removes the rule from the parse tree when it has one child. `-> name` gives a name to the tree node of an alternative.
- `!rule` keeps the keywords of the rule in the parse tree.
- `x*` is zero or more `x`, `x+` is one or more, and `x?` is optional.

## Precedence

From the tightest to the loosest. Each level is left-associative, and parentheses group:

| Level | Operators |
| --- | --- |
| 1 | `+` `-`: a datetime plus or minus a duration |
| 2 | `in`, `has any`, `has all`, `contains`, `startswith`, `endswith`, `is null`, `is not null` |
| 3 | `==` `!=` `<` `<=` `>` `>=` |
| 4 | `not` |
| 5 | `and` |
| 6 | `or` |

A comparison does not chain: `a < b < c` is a syntax error. The right side of `+` and `-` is a duration literal. The only arithmetic is a datetime plus or minus a duration.

## Lexical rules

- **Comments** start with `//` and stop at the end of the line.
- **Strings** are in double quotes. The escapes are the JSON escapes: `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t` and `\uXXXX`. Another escape is an error. A control character, a newline included, is an error in a string: write it with an escape.
- **Numbers** are an integer or a decimal, with an optional leading `-`. There is no exponent.
- **Durations** are an integer and a unit: `s`, `m` (minutes), `h`, `d` or `w`. For example `7d`.
- **Booleans** are `true` and `false`. There is no `null` literal: use `is null`, `is not null` or `isPresent(x)`.
- **Lists** are one or more literals in parentheses, with no trailing comma. A list is the right side of `in`, `has any` and `has all` only.
- **Paths** select keys with dots and array elements with brackets. `machine.tags[0].name` selects element 0, `machine.tags[].name` selects every element, and `machine.tags.0` selects a key named `0`.
- **Backticks** quote a key that is not an identifier, for example ``machine.`workspace-one`.name``. A backtick key cannot contain a dot: a dot is always a separator.
- **Keywords** are lowercase, and the language is case-sensitive.
- A keyword is a keyword only where the grammar accepts one. `stats count() by by` groups on a field named `by`, and `where by == "x"` filters on it.
- At the start of an expression, and in an alias, `not`, `true`, `false`, `null` and `linked` are not names. After a dot, every word is a name: `payload.true` selects the key `true`. At the start of a path, use backticks: `` `true` ``.
- An entity type, for example `Santa::Configuration`, is only the first argument of `linked()`.

## The grammar

```lark
// ZQL, the Zentral query language.
//
// A query is a source, then stages separated by "|".
// Load with parser="lalr" (the default lexer is the contextual lexer).
// The contextual lexer emits a keyword only where the grammar accepts one,
// so "by" in "stats count() by by" and in "where by == 1" is a field name.

start: query

query: source ("|" stage)*

source: NAME

?stage: where
      | stats
      | sort
      | limit
      | fields
      | paths

where: "where" expr

stats: "stats" aggregation ("," aggregation)* group_by?
aggregation: call alias?

paths: "paths" group_by?

group_by: "by" group_key ("," group_key)*
group_key: expr alias?

alias: "as" IDENTIFIER

sort: "sort" sort_key ("," sort_key)*
sort_key: expr sort_order?
!sort_order: "asc" | "desc"

limit: "limit" INT

fields: "fields" key ("," key)*

// Precedence, loosest first. Each level is left-associative.
// A comparison does not chain: "a < b < c" is a syntax error.

?expr: or_expr

?or_expr: and_expr
        | or_expr "or" and_expr -> or_

?and_expr: not_expr
         | and_expr "and" not_expr -> and_

?not_expr: comparison
         | "not" not_expr -> not_

?comparison: membership
           | membership COMPARISON_OPERATOR membership -> compare

?membership: arithmetic
           | membership "in" list -> in_
           | membership "has" "any" list -> has_any
           | membership "has" "all" list -> has_all
           | membership "contains" arithmetic -> contains
           | membership "startswith" arithmetic -> startswith
           | membership "endswith" arithmetic -> endswith
           | membership "is" "null" -> is_null
           | membership "is" "not" "null" -> is_not_null

// The only arithmetic: a datetime plus or minus a duration.
?arithmetic: atom
           | arithmetic ARITHMETIC_OPERATOR DURATION -> datetime_arithmetic

?atom: literal
     | call
     | linked
     | path
     | "(" expr ")"

call: IDENTIFIER "(" (expr ("," expr)*)? ")"

// An entity type appears in this production only.
linked: "linked" "(" (ENTITY_TYPE | STRING) ("," linked_value)+ ")"
?linked_value: STRING | NUMBER

path: (IDENTIFIER | QUOTED_KEY) segment*
segment: "." (key | INT) -> member
        | "[" INT "]" -> index
        | "[" "]" -> flatten
?key: NAME | QUOTED_KEY

list: "(" list_item ("," list_item)* ")"
?list_item: STRING | NUMBER | DURATION | boolean

?literal: STRING | NUMBER | DURATION | boolean
!boolean: "true" | "false"

COMPARISON_OPERATOR: "==" | "!=" | "<=" | ">=" | "<" | ">"
ARITHMETIC_OPERATOR: "+" | "-"

NAME: /[A-Za-z_][A-Za-z0-9_]*/
// A name at the start of an expression, and an alias, which a later stage reads as a path.
// The keywords that can start an expression are not names there, so a key named "true" takes backticks
// at the head of a path, and reads as a name after a dot.
// "null" is not a name there either, so "x == null" is a syntax error and not a path that matches nothing.
IDENTIFIER: /(?!(not|true|false|null|linked)(?![A-Za-z0-9_]))[A-Za-z_][A-Za-z0-9_]*/
ENTITY_TYPE: /[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)+/
// A key that is not an identifier: a space, a hyphen. Never a dot, which is always a separator.
QUOTED_KEY: /`[^`.\n]+`/
INT: /[0-9]+/
NUMBER: /-?[0-9]+(\.[0-9]+)?(?![A-Za-z0-9_.])/
DURATION: /[0-9]+[smhdw](?![A-Za-z0-9_])/
// The JSON escapes. A control character, a newline included, is written with an escape.
STRING: /"([^"\\\x00-\x1f]|\\(["\\\/bfnrt]|u[0-9a-fA-F]{4}))*"/

COMMENT: /\/\/[^\n]*/
%import common.WS
%ignore WS
%ignore COMMENT
```
