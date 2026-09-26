# Draft upstream issue: pySigma-backend-elasticsearch ES|QL LIKE escaping

Draft for [SigmaHQ/pySigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/issues). **Not filed.** This repository works around the problem in `scripts/backends.py`.

---

**Title:** ES|QL: literal backslash in `contains`/wildcard values produces an invalid `LIKE` pattern

**Versions:** pySigma 1.5.1, pySigma-backend-elasticsearch 2.1.1, Elasticsearch 9.1.5

**Rule excerpt:**

```yaml
detection:
    selection:
        Image|contains: '\claude\versions\'
    condition: selection
```

**Generated ES|QL:**

```
from * metadata _id, _index, _version | where Image like "*\\claude\\versions\\*"
```

**Result on Elasticsearch 9.1.5:**

```
line 1:…: Invalid pattern for LIKE [*\claude\versions\*]:
[Invalid sequence - escape character is not followed by special wildcard char]
```

**Cause:** the string literal `"*\\claude\\versions\\*"` becomes the pattern `*\claude\versions\*`. In ES|QL `LIKE`, `\` is the pattern escape character and may only precede `*`, `?` or `\`. A literal backslash therefore has to be `\\` in the *pattern*, which is `\\\\` inside a regular string literal (or `\\` inside a `"""…"""` literal).

The same value in `==`, `starts_with()` or `ends_with()` is correct as emitted. Only `LIKE` (`wildcard_match_expression`) needs the extra level of escaping.

**Expected:**

```
from * metadata _id, _index, _version | where Image like "*\\\\claude\\\\versions\\\\*"
```

This parses and matches `C:\Users\u\.local\claude\versions\2.1.0` on 9.1.5.

**Suggested fix:** when a value is rendered for `wildcard_match_expression`, escape backslashes for the pattern layer as well as the string layer, for example by overriding `convert_condition_field_eq_val_str` or providing a separate value-escaping path for LIKE.

**Related, possibly worth separate issues:**

1. **Case sensitivity.** Sigma matches strings case-insensitively, but the ES|QL output uses case-sensitive `==`, `in`, `like`, `starts_with` and `ends_with`. `to_lower(field) <op> "<lower-cased value>"` restores Sigma semantics.
2. **Correlation windows.** `date_trunc(<timespan>, @timestamp)` produces tumbling buckets, so a `value_count` burst that straddles a bucket boundary (for example 03:50, 03:52, 04:10 with `timespan: 1h`) is never counted together.
