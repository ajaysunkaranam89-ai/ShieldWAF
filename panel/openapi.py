"""OpenAPI 3 request validation, compiled into ModSecurity rules (so it runs inside the engine, no extra service).

Enforced for every operation in the document:
  * the path template (path parameters of type integer / enum are matched strictly), unknown paths (optional), and the allowed methods (405)
  * query parameters: unknown names, required ones, integer / number / boolean / enum types, numeric minimum / maximum
  * request body (application/json): allowed content type, required fields, unknown fields (strict), field types
    (integer, number, boolean, enum), string minLength / maxLength, numeric minimum / maximum, nested objects and arrays
Limits (reported, never silently ignored): oneOf / anyOf / allOf / not, formats, patterns, and the difference between a JSON string and a JSON
number (ModSecurity sees both as text) are not enforced. Only local $ref (#/components/...) is resolved. JSON only (convert YAML first).
Mode "detect" logs violations without blocking; "enforce" refuses them (400 / 404 / 405)."""
import json
import re

ARR = r"array_\d+"          # how ModSecurity names array elements: json.tags.array_1, json.tags.array_2, ...
MAX_SPEC = 1024 * 1024
MAX_OPS = 150
NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
ENUM_RE = re.compile(r"^[A-Za-z0-9_ .:/@+\-]{0,100}$")
METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
UNSUPPORTED = ("oneOf", "anyOf", "allOf", "not", "discriminator", "pattern", "format")


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


def _flatten(spec, schema, prefix, depth, fields, report, where, required=True):
    """Collect (name_regex, schema, required) for every scalar leaf of a JSON body schema."""
    schema = _resolve(spec, schema) or {}
    for k in UNSUPPORTED:
        if k in schema and k not in ("pattern", "format"):
            report.append(f"not enforced: '{k}' in {where}")
    t = schema.get("type", "object" if "properties" in schema else None)
    if t == "object" and depth < 4:
        props = schema.get("properties", {}) or {}
        req = set(schema.get("required", []) or [])
        for name, sub in props.items():
            if not NAME_RE.match(name):
                report.append(f"not enforced: odd property name in {where}")
                continue
            _flatten(spec, sub, f"{prefix}.{name}", depth + 1, fields, report, where, required and name in req)
    elif t == "array" and depth < 4:
        _flatten(spec, schema.get("items", {}), f"{prefix}.{ARR}", depth + 1, fields, report, where, False)
    else:
        fields.append((prefix, schema, required))


def _value_rules(var, schema, rid, act, label, out):
    """Rules for the VALUE of a variable (type, enum, length, range). Returns the next free id."""
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
        if isinstance(schema.get("minimum"), (int, float)) and not isinstance(schema["minimum"], bool):
            checks.append((f'"@lt {schema["minimum"]}"', f"{label} below minimum"))
        if isinstance(schema.get("maximum"), (int, float)) and not isinstance(schema["maximum"], bool):
            checks.append((f'"@gt {schema["maximum"]}"', f"{label} above maximum"))
    if t == "string":
        if isinstance(schema.get("maxLength"), int) and 0 <= schema["maxLength"] <= 100000:
            checks.append((f'"@rx ^.{{{schema["maxLength"] + 1},}}$"', f"{label} too long"))
        if isinstance(schema.get("minLength"), int) and 1 <= schema["minLength"] <= 100000:
            checks.append((f'"@rx ^.{{0,{schema["minLength"] - 1}}}$"', f"{label} too short"))
    return checks


def compile_rules(text, mode="detect", strict_fields=True, unknown_paths="allow", first_id=2000000):
    """Return (rules_text, report_lines). Raises SpecError for an unusable document."""
    if len(text) > MAX_SPEC:
        raise SpecError("OpenAPI document larger than 1 MB")
    try:
        spec = json.loads(text)
    except ValueError as e:
        raise SpecError(f"not valid JSON ({e}); convert YAML to JSON first") from None
    if not isinstance(spec, dict) or not str(spec.get("openapi", "")).startswith("3."):
        raise SpecError("this is not an OpenAPI 3.x document (missing 'openapi: 3.x')")
    paths = spec.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise SpecError("the document has no paths")
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
            # path parameters can be typed per operation too
            oprx = _path_regex(template, params, spec)
            if oprx[1:-3] not in path_rx:
                path_rx.append(oprx[1:-3])
            head = f'SecRule REQUEST_FILENAME "@rx {oprx}" "id:{{id}},phase:{{ph}},{{act}},msg:\'OpenAPI {m.upper()} {_q(template)}: {{msg}}\',chain"\n  SecRule REQUEST_METHOD "@streq {m.upper()}" "chain"\n'
            enforced = []

            def add(ph, status, msg, var_rule):
                rules.append(head.format(id=nid(), ph=ph, act=act(status), msg=_q(msg)) + f"  SecRule {var_rule}")

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
                for cond, msg in _value_rules(f"ARGS_GET:{n}", sch, 0, None, f"query {n}", []):
                    add(1, 400, msg, f"ARGS_GET:{n} {cond} \"\"")
            enforced.append(f"{len(qnames)} query parameter(s)")
            rb = _resolve(spec, op.get("requestBody", {})) or {}
            content = rb.get("content", {}) if isinstance(rb, dict) else {}
            if content:
                ctypes = [c.split(";")[0].strip().lower() for c in content]
                ct_alt = "|".join(_rx_escape(c) for c in ctypes if re.fullmatch(r"[a-z0-9.+/-]+", c))
                if ct_alt:
                    add(1, 415 if enforce else 400, "content type not allowed", f'REQUEST_HEADERS:Content-Type "!@rx ^(?:{ct_alt})(?:;|$)" ""')
                js = next((v for k, v in content.items() if k.split(";")[0].strip().lower() == "application/json"), None)
                if js is not None:
                    fields = []
                    _flatten(spec, (js or {}).get("schema", {}), "json", 0, fields, report, f"{m.upper()} {_q(template)}", True)
                    names = []
                    nreq = 0
                    for fname, sch, req in fields:
                        names.append(fname)
                        if req and rb.get("required", False) is not False:
                            nreq += 1
                            add(2, 400, f"missing field {fname[5:]}", f'&ARGS:{fname} "@eq 0" ""')
                        for cond, msg in _value_rules(f"ARGS:{fname}", sch, 0, None, f"field {fname[5:]}", []):
                            add(2, 400, msg, f"ARGS:{fname} {cond} \"\"")
                    if strict_fields and names:
                        rel = []
                        for n in names:
                            parts = n[5:].split(".")           # drop "json."
                            rel.append(r"\.".join(pt if pt == ARR else _rx_escape(pt) for pt in parts))
                        add(2, 400, "unknown field", r'ARGS_NAMES "@rx ^json\.(?!(?:' + "|".join(rel) + r')$)" ""')
                    enforced.append(f"{len(names)} body field(s), {nreq} required")
            report.append(f"enforced: {m.upper()} {template} ({', '.join(enforced)})")
    if unknown_paths == "deny" and path_rx:
        rules.append(f'SecRule REQUEST_FILENAME "!@rx ^(?:{"|".join(path_rx)})/?$" "id:{nid()},phase:1,{act(404)},msg:\'OpenAPI: unknown path\'"')
    header = ["# ---- compiled from the OpenAPI document (do not edit by hand) ----",
              'SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:2000000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"']
    return "\n".join(header + rules) + "\n", report
