"""OpenAPI 3 request validation, compiled into ModSecurity rules (so it runs inside the engine, no extra service).

Enforced for every operation in the document:
  * the path template (path parameters of type integer / enum are matched strictly), unknown paths (optional), and the allowed methods (405)
  * query parameters: unknown names, required ones, integer / number / boolean / enum types, numeric minimum / maximum
  * request body (application/json): allowed content type, required fields at any depth (also inside optional objects, and inside array items for the
    first 25 elements), unknown fields (strict), field types, string minLength / maxLength / pattern (safe subset) / format (uuid, date, date-time, email, ipv4),
    numeric minimum / maximum / exclusive bounds, maxItems, allOf (merged), nested objects and arrays
  * per operation: a request body size limit (413) and a JSON nesting limit (400)
Limits (reported, never silently ignored): oneOf / anyOf / not / uniqueItems, other formats, patterns that look expensive, properties more than 6 levels
deep, and the difference between a JSON string and a JSON number (ModSecurity sees both as text) are not enforced. Only local $ref (#/components/...) is
resolved; reference chains and the number of schema nodes are bounded. JSON only (convert YAML first).
Mode "detect" logs violations without blocking; "enforce" refuses them (400 / 404 / 405)."""
import json
import re

ARR = r"array_\d+"          # how ModSecurity names array elements: json.tags.array_1, json.tags.array_2, ...
MAX_SPEC = 1024 * 1024
MAX_OPS = 150
NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
ENUM_RE = re.compile(r"^[A-Za-z0-9_ .:/@+\-]{0,100}$")
METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
UNSUPPORTED = ("oneOf", "anyOf", "not", "discriminator", "uniqueItems")      # reported, never silently ignored (allOf is merged for objects)
MAX_DEPTH = 6              # object nesting levels described by the schema; deeper properties are accepted unchecked (and reported)
ARRAY_CHECK = 25           # elements per array whose required properties are checked one by one (a longer array is refused in that case)
MAX_NODES = 4000           # compile-time budget: schema nodes visited (protects the panel from hostile or accidental huge schemas)
FORMATS = {
    "uuid": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    "date": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
    "date-time": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})$",
    "email": r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,}$",
    "ipv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
}
SAFE_PATTERN_CHARS = re.compile(r"^[A-Za-z0-9 _.,:;@/\\^$()\[\]{}|*+?\-]{1,200}$")
NESTED_QUANTIFIER = re.compile(r"\([^)]*[*+][^)]*\)[*+{]")       # (a+)+ style: the classic catastrophic-backtracking shape


class SpecError(ValueError):
    pass


def _resolve(spec, node, depth=0):
    if depth > 10:
        raise SpecError("$ref nesting too deep")
    if isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise SpecError("only local $ref (#/components/...) is supported")
        cur = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(cur, dict) or part not in cur:
                raise SpecError(f"unresolved reference {ref}")
            cur = cur[part]
        return _resolve(spec, cur, depth + 1)
    return node


def _rx_escape(s):
    return re.sub(r"([.^$*+?()\[\]{}|\\/-])", r"\\\1", s)


def _q(s):
    """Make a string safe inside a ModSecurity single-quoted msg."""
    return re.sub(r"[^A-Za-z0-9 _./{}:,-]", "", str(s))[:80]


def _path_regex(template, params, spec):
    out = []
    for seg in re.split(r"(\{[^}]+\})", template):
        if seg.startswith("{") and seg.endswith("}"):
            name = seg[1:-1]
            sch = _resolve(spec, params.get(name, {}).get("schema", {}), 0) or {}
            if sch.get("enum") and all(isinstance(e, (str, int)) and ENUM_RE.match(str(e)) for e in sch["enum"]):
                out.append("(?:" + "|".join(_rx_escape(str(e)) for e in sch["enum"]) + ")")
            elif sch.get("type") == "integer":
                out.append("-?[0-9]+")
            elif sch.get("type") == "number":
                out.append("-?[0-9]+(?:\\.[0-9]+)?")
            elif sch.get("type") == "boolean":
                out.append("(?:true|false)")
            else:
                out.append("[^/]+")
        else:
            out.append(_rx_escape(seg))
    return "^" + "".join(out) + "/?$"


def _merge_allof(spec, schema, depth=0):
    """allOf of object schemas is the union of their properties and required lists."""
    schema = _resolve(spec, schema) or {}
    if not isinstance(schema, dict) or "allOf" not in schema or depth > 5:
        return schema if isinstance(schema, dict) else {}
    merged = {k: v for k, v in schema.items() if k != "allOf"}
    props, req = dict(merged.get("properties") or {}), list(merged.get("required") or [])
    for part in schema["allOf"] if isinstance(schema["allOf"], list) else []:
        part = _merge_allof(spec, part, depth + 1)
        for k, v in part.items():
            if k == "properties":
                props.update(v or {})
            elif k == "required":
                req += list(v or [])
            elif k not in merged:
                merged[k] = v
    if props:
        merged["properties"] = props
        merged.setdefault("type", "object")
    if req:
        merged["required"] = sorted(set(req))
    return merged


def _esc_prefix(prefix):
    """A dotted variable name as a regex; the array element placeholder stays a pattern."""
    return r"\.".join(pt if pt == ARR else _rx_escape(pt) for pt in prefix.split("."))


def _var(prefix):
    """ARGS selector for a field: exact name, or a regex selector when the name passes through array elements."""
    return f"ARGS:/^{_esc_prefix(prefix)}$/" if ARR in prefix else f"ARGS:{prefix}"


def _gt_regex(n):
    """Regex for decimal integers greater than n (array element numbers)."""
    s = str(n)
    alts = [f"[1-9][0-9]{{{len(s)},}}"]
    for i, ch in enumerate(s):
        d = int(ch)
        if d < 9:
            rng = f"[{d + 1}-9]" if d + 1 < 9 else "9"
            alts.append(re.escape(s[:i]) + rng + (f"[0-9]{{{len(s) - i - 1}}}" if len(s) - i - 1 else ""))
    return "|".join(alts)


def _safe_pattern(p):
    return isinstance(p, str) and bool(SAFE_PATTERN_CHARS.match(p)) and "(?" not in p and not re.search(r"\\[1-9]", p) and not NESTED_QUANTIFIER.search(p)


class _Ctx:
    def __init__(self, where, report):
        self.where, self.report = where, report
        self.fields = []        # (name, schema) of every scalar leaf: value rules and the unknown-field list
        self.required = []      # (condition prefix or None, leaf name): the leaf must exist (when the condition prefix exists)
        self.arrays = []        # (array prefix, first forbidden element number, label)
        self.mins = []          # (required array prefix, minItems, items are scalars): an empty array looks exactly like a missing field
        self.opaque = []        # prefixes below which anything is accepted (deeper than the limit, or additionalProperties)
        self.nodes = 0
        self.said = set()

    def say(self, msg):
        if msg not in self.said:
            self.said.add(msg)
            self.report.append(msg)


def _has_required(spec, schema, depth=0):
    schema = _merge_allof(spec, schema)
    if depth > 4 or schema.get("type", "object" if "properties" in schema else None) != "object":
        return False
    props = schema.get("properties") or {}
    return any(n in props for n in (schema.get("required") or [])) or any(_has_required(spec, v, depth + 1) for v in props.values() if isinstance(v, dict))


def _walk(spec, ctx, schema, prefix, depth, state, req_only=False):
    """state = (always, cond): `always` = every ancestor is required; `cond` = nearest optional ancestor (required children matter only if it is present)."""
    schema = _merge_allof(spec, schema)
    ctx.nodes += 1
    if ctx.nodes > MAX_NODES:
        raise SpecError(f"the schema is too large or too deeply nested to compile (more than {MAX_NODES} nodes)")
    if not req_only:
        for k in UNSUPPORTED:
            if k in schema:
                ctx.say(f"not enforced: '{k}' in {ctx.where}")
    t = schema.get("type", "object" if "properties" in schema else ("array" if "items" in schema else None))
    if t == "object":
        if depth >= MAX_DEPTH:
            if not req_only:
                ctx.opaque.append(prefix)
                ctx.say(f"not enforced: properties more than {MAX_DEPTH} levels deep in {ctx.where} are accepted without checks")
            return
        props, req = schema.get("properties") or {}, set(schema.get("required") or [])
        if not req_only and ((props and schema.get("additionalProperties") not in (None, False)) or (not props and schema.get("additionalProperties") is not False)):
            ctx.opaque.append(prefix)                   # free-form object (or additionalProperties allowed): anything below it is accepted
        for name, sub in props.items():
            if not NAME_RE.match(name):
                ctx.say(f"not enforced: odd property name in {ctx.where}")
                continue
            child = f"{prefix}.{name}"
            _walk(spec, ctx, sub, child, depth + 1, state if name in req else (False, child), req_only)
    elif t == "array":
        if depth >= MAX_DEPTH:
            if not req_only:
                ctx.opaque.append(prefix)
                ctx.say(f"not enforced: properties more than {MAX_DEPTH} levels deep in {ctx.where} are accepted without checks")
            return
        if req_only:
            return
        items = _merge_allof(spec, schema.get("items") or {})
        mx = schema.get("maxItems") if isinstance(schema.get("maxItems"), int) and not isinstance(schema.get("maxItems"), bool) and schema["maxItems"] >= 0 else None
        _walk(spec, ctx, items, f"{prefix}.{ARR}", depth + 1, (False, None))
        if _has_required(spec, items):
            k = min(ARRAY_CHECK, mx) if mx is not None else ARRAY_CHECK
            for i in range(k):
                _walk(spec, ctx, items, f"{prefix}.array_{i}", depth + 1, (False, f"{prefix}.array_{i}"), True)
            ctx.arrays.append((prefix, k, f"maxItems {mx}" if mx is not None and mx <= ARRAY_CHECK else f"the {ARRAY_CHECK} elements that are checked one by one"))
        elif mx is not None and mx <= 10000:
            ctx.arrays.append((prefix, mx, f"maxItems {mx}"))
        mn = schema.get("minItems")
        if isinstance(mn, int) and not isinstance(mn, bool) and mn >= 1:
            if state[0] and ARR not in prefix:
                ctx.mins.append((prefix, mn, items.get("type") in ("string", "integer", "number", "boolean")))
            else:
                ctx.say(f"not enforced: minItems of an optional array in {ctx.where} (an empty array cannot be told from a missing one)")
        elif state[0]:
            ctx.say(f"note: a required array in {ctx.where} is not refused when it is missing, because ModSecurity cannot tell a missing array from an empty one (set minItems: 1 to require elements)")
    else:
        always, cond = state
        if not req_only:
            ctx.fields.append((prefix, schema))
        if always and ARR not in prefix:
            ctx.required.append((None, prefix))
        elif cond and cond != prefix and ARR not in prefix and ARR not in cond:
            ctx.required.append((cond, prefix))


def _value_rules(var, schema, label):
    """Rules for the VALUE of a variable (type, enum, length, range, pattern, format). Returns [(operator text or None, message)]; None = not enforced."""
    t = schema.get("type")
    checks = []
    enum = schema.get("enum")
    if enum and all(isinstance(e, (str, int, float, bool)) and ENUM_RE.match(str(e).lower() if isinstance(e, bool) else str(e)) for e in enum):
        vals = [("true" if e else "false") if isinstance(e, bool) else str(e) for e in enum]
        checks.append((f'"!@rx ^(?:{"|".join(_rx_escape(v) for v in vals)})$"', f"{label} not in enum"))
    elif t == "integer":
        checks.append(('"!@rx ^-?[0-9]+$"', f"{label} must be an integer"))
    elif t == "number":
        checks.append(('"!@rx ^-?[0-9]+(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$"', f"{label} must be a number"))
    elif t == "boolean":
        checks.append(('"!@rx ^(?:true|false)$"', f"{label} must be true or false"))
    if t in ("integer", "number"):
        def num(k):
            return isinstance(schema.get(k), (int, float)) and not isinstance(schema[k], bool)
        if num("minimum"):
            checks.append((f'"@lt {schema["minimum"]}"', f"{label} below minimum"))
        if num("maximum"):
            checks.append((f'"@gt {schema["maximum"]}"', f"{label} above maximum"))
        if num("exclusiveMinimum"):
            checks.append((f'"@le {schema["exclusiveMinimum"]}"', f"{label} not above the exclusive minimum"))
        if num("exclusiveMaximum"):
            checks.append((f'"@ge {schema["exclusiveMaximum"]}"', f"{label} not below the exclusive maximum"))
    if t == "string":
        if isinstance(schema.get("maxLength"), int) and 0 <= schema["maxLength"] <= 100000:
            checks.append((f'"@rx ^.{{{schema["maxLength"] + 1},}}$"', f"{label} too long"))
        if isinstance(schema.get("minLength"), int) and 1 <= schema["minLength"] <= 100000:
            checks.append((f'"@rx ^.{{0,{schema["minLength"] - 1}}}$"', f"{label} too short"))
        pat = schema.get("pattern")
        if pat is not None:
            if _safe_pattern(pat):
                checks.append(('"!@rx ' + pat.replace('"', '\\"') + '"', f"{label} does not match the pattern"))
            else:
                checks.append((None, f"not enforced: pattern of {label} (too complex or unsafe to run in the firewall)"))
        fmt = schema.get("format")
        if fmt in FORMATS:
            checks.append((f'"!@rx {FORMATS[fmt]}"', f"{label} is not a valid {fmt}"))
        elif fmt:
            checks.append((None, f"not enforced: format '{fmt}' of {label}"))
    return checks


def compile_rules(text, mode="detect", strict_fields=True, unknown_paths="allow", first_id=2000000, max_body_kb=1024, max_depth=10):
    """Return (rules_text, report_lines). Raises SpecError for an unusable document."""
    if len(text) > MAX_SPEC:
        raise SpecError("OpenAPI document larger than 1 MB")
    try:
        spec = json.loads(text)
    except (ValueError, RecursionError):
        raise SpecError("not valid JSON (or nested too deeply); convert YAML to JSON first") from None
    if not isinstance(spec, dict) or not str(spec.get("openapi", "")).startswith("3."):
        raise SpecError("this is not an OpenAPI 3.x document (missing 'openapi: 3.x')")
    paths = spec.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise SpecError("the document has no paths")
    max_body_kb, max_depth = max(1, min(int(max_body_kb), 1024 * 1024)), max(2, min(int(max_depth), 64))
    enforce = mode == "enforce"
    rid = [first_id]
    rules, report, path_rx = [], [], []

    def nid():
        rid[0] += 1
        return rid[0]

    def act(status):
        return f"deny,status:{status},log,auditlog" if enforce else "pass,log,auditlog"

    n_ops = 0
    for template, item in paths.items():
        item = _resolve(spec, item) or {}
        if not isinstance(template, str) or not re.fullmatch(r"/[A-Za-z0-9_\-./{}~]*", template):
            report.append(f"skipped: unusual path {_q(template)}")
            continue
        common_params = {p["name"]: p for p in (_resolve(spec, x) for x in item.get("parameters", []) or []) if isinstance(p, dict) and "name" in p}
        ops = {m: _resolve(spec, item[m]) for m in METHODS if m in item}
        if not ops:
            continue
        prx = _path_regex(template, {**common_params}, spec)
        allowed = "|".join(m.upper() for m in ops)
        rules.append(f'SecRule REQUEST_FILENAME "@rx {prx}" "id:{nid()},phase:1,{act(405)},msg:\'OpenAPI: method not allowed on {_q(template)}\',chain"\n'
                     f'  SecRule REQUEST_METHOD "!@rx ^(?:{allowed})$" ""')
        for m, op in ops.items():
            n_ops += 1
            if n_ops > MAX_OPS:
                raise SpecError(f"more than {MAX_OPS} operations; split the document")
            op = op or {}
            params = {**common_params, **{p["name"]: p for p in (_resolve(spec, x) for x in op.get("parameters", []) or []) if isinstance(p, dict) and "name" in p}}
            oprx = _path_regex(template, params, spec)
            if oprx[1:-3] not in path_rx:
                path_rx.append(oprx[1:-3])
            head = f'SecRule REQUEST_FILENAME "@rx {oprx}" "id:{{id}},phase:{{ph}},{{act}},msg:\'OpenAPI {m.upper()} {_q(template)}: {{msg}}\',chain"\n  SecRule REQUEST_METHOD "@streq {m.upper()}" "chain"\n'
            enforced = []

            def add(ph, status, msg, var_rule, pre=None):
                rules.append(head.format(id=nid(), ph=ph, act=act(status), msg=_q(msg)) + (f'  SecRule {pre} "chain"\n' if pre else "") + f"  SecRule {var_rule}")

            def unenforced(msg):
                if msg not in report:
                    report.append(msg)

            query = {n: p for n, p in params.items() if p.get("in") == "query"}
            qnames = [n for n in query if NAME_RE.match(n)]
            if qnames:
                add(1, 400, "unknown query parameter", f'ARGS_GET_NAMES "@rx ^(?!(?:{"|".join(_rx_escape(n) for n in qnames)})$)" ""')
            else:
                add(1, 400, "query parameters are not allowed", '&ARGS_GET "@gt 0" ""')
            for n in qnames:
                p = query[n]
                sch = _resolve(spec, p.get("schema", {})) or {}
                if p.get("required"):
                    add(1, 400, f"missing query parameter {n}", f'&ARGS_GET:{n} "@eq 0" ""')
                for cond, msg in _value_rules(f"ARGS_GET:{n}", sch, f"query {n}"):
                    if cond is None:
                        unenforced(msg)
                    else:
                        add(1, 400, msg, f"ARGS_GET:{n} {cond} \"\"")
            enforced.append(f"{len(qnames)} query parameter(s)")
            rb = _resolve(spec, op.get("requestBody", {})) or {}
            content = rb.get("content", {}) if isinstance(rb, dict) else {}
            if content:
                ctypes = [c.split(";")[0].strip().lower() for c in content]
                ct_alt = "|".join(_rx_escape(c) for c in ctypes if re.fullmatch(r"[a-z0-9.+/-]+", c))
                if ct_alt:
                    add(1, 415 if enforce else 400, "content type not allowed", f'REQUEST_HEADERS:Content-Type "!@rx ^(?:{ct_alt})(?:;|$)" ""')
                add(1, 413, f"request body larger than {max_body_kb} KB", f'REQUEST_HEADERS:Content-Length "@gt {max_body_kb * 1024}" ""')
                js = next((v for k, v in content.items() if k.split(";")[0].strip().lower() == "application/json"), None)
                if js is not None:
                    ctx = _Ctx(f"{m.upper()} {_q(template)}", report)
                    _walk(spec, ctx, (js or {}).get("schema", {}), "json", 0, (True, None))
                    body_required = rb.get("required", False) is not False
                    names = [n for n, _ in ctx.fields]
                    nreq = 0
                    if body_required:
                        for cond, leaf in ctx.required:
                            nreq += 1
                            if cond is None:
                                add(2, 400, f"missing field {leaf[5:]}", f'&ARGS:{leaf} "@eq 0" ""')
                            else:
                                add(2, 400, f"missing field {leaf[5:]} (its parent {cond[5:]} is present)", f'&ARGS:{leaf} "@eq 0" ""', pre=f'&ARGS:/^{_esc_prefix(cond)}\\./ "@gt 0"')
                    for fname, sch in ctx.fields:
                        for cond, msg in _value_rules(_var(fname), sch, f"field {fname[5:]}"):
                            if cond is None:
                                unenforced(msg)
                            else:
                                add(2, 400, msg, f"{_var(fname)} {cond} \"\"")
                    for prefix, k, label in ctx.arrays:
                        rx = _gt_regex(k - 1) if k >= 1 else "[0-9]+"
                        add(2, 400, f"too many items in {prefix[5:]} (at most {label})", f'ARGS_NAMES "@rx ^{_esc_prefix(prefix)}\\.array_(?:{rx})(?:\\.|$)" ""')
                    if body_required:
                        for prefix, mn, scalar in ctx.mins:
                            if scalar and mn > 1:
                                add(2, 400, f"too few items in {prefix[5:]} (at least {mn})", f'&ARGS:/^{_esc_prefix(prefix)}\\.array_[0-9]+$/ "@lt {mn}" ""')
                            else:
                                add(2, 400, f"missing or empty array {prefix[5:]}", f'&ARGS:/^{_esc_prefix(prefix)}\\.array_[0-9]+(?:\\.|$)/ "@eq 0" ""')
                    deepest = max([n.count(".") for n in names] + [0])
                    limit = max(max_depth, deepest + 1)
                    add(2, 400, f"JSON nested deeper than {limit} levels", f'ARGS_NAMES "@rx ^json(?:\\.[^.]+){{{limit + 1},}}$" ""')
                    if strict_fields and (names or ctx.opaque):
                        rel = [_esc_prefix(n[5:]) for n in names] + [_esc_prefix(o[5:]) + r"(?:\.[^ ]+)?" for o in ctx.opaque if o != "json"]
                        if "json" in ctx.opaque:
                            rel = [r"[^ ]+"]
                        add(2, 400, "unknown field", r'ARGS_NAMES "@rx ^json\.(?!(?:' + "|".join(rel) + r')$)" ""')
                    enforced.append(f"{len(names)} body field(s), {nreq} required, body limit {max_body_kb} KB, depth {limit}")
            report.append(f"enforced: {m.upper()} {template} ({', '.join(enforced)})")
    if unknown_paths == "deny" and path_rx:
        rules.append(f'SecRule REQUEST_FILENAME "!@rx ^(?:{"|".join(path_rx)})/?$" "id:{nid()},phase:1,{act(404)},msg:\'OpenAPI: unknown path\'"')
    header = ["# ---- compiled from the OpenAPI document (do not edit by hand) ----",
              'SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:2000000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"']
    return "\n".join(header + rules) + "\n", report
