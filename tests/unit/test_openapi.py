"""OpenAPI validation tests. The rules are compiled by panel/openapi.py and run in the REAL engine (nginx + ModSecurity v3 from the shieldwaf image) in front of
a tiny backend, so every case checks what a client would actually see: 200 = reached the backend, 4xx = refused by the compiled rules. Skipped when nginx is missing."""
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "panel"))
import openapi  # noqa: E402

NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if os.path.exists("/usr/sbin/nginx") else None)
MODSEC = "/etc/nginx/modules/ngx_http_modsecurity_module.so"
HAVE_ENGINE = bool(NGINX) and os.path.exists(MODSEC)


def deep(levels):
    d = {"x": 1}
    for _ in range(levels):
        d = {"n": d}
    return d


ORDER = {
    "type": "object", "required": ["id", "customer", "items", "labels"],
    "properties": {
        "id": {"type": "integer", "minimum": 1, "maximum": 1000000},
        "customer": {"type": "object", "required": ["name"], "properties": {
            "name": {"type": "string", "minLength": 2, "maxLength": 20}, "email": {"type": "string", "format": "email"}}},
        "items": {"type": "array", "maxItems": 5, "items": {"type": "object", "required": ["sku", "qty"], "properties": {
            "sku": {"type": "string", "pattern": "^[A-Z]{3}-[0-9]{4}$"}, "qty": {"type": "integer", "minimum": 1, "maximum": 100}}}},
        "address": {"type": "object", "required": ["city"], "properties": {"city": {"type": "string"}, "zip": {"type": "string"}}},
        "status": {"type": "string", "enum": ["new", "paid"]},
        "ref": {"type": "string", "format": "uuid"},
        "score": {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 10},
        "tags": {"type": "array", "items": {"type": "string"}},
        "labels": {"type": "array", "minItems": 2, "items": {"type": "string"}},
        "meta": {"type": "object", "additionalProperties": True},
        "extended": {"allOf": [{"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}},
                               {"type": "object", "required": ["b"], "properties": {"b": {"type": "string"}}}]},
    },
}
SPEC = {
    "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
    "paths": {
        "/orders": {"post": {"requestBody": {"required": True, "content": {"application/json": {"schema": ORDER}}}}},
        "/orders/{id}": {"get": {"parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
            {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}]}},
    },
}


class Backend(http.server.BaseHTTPRequestHandler):
    def _ok(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = do_PUT = do_DELETE = _ok

    def log_message(self, *a):
        pass


@unittest.skipUnless(HAVE_ENGINE, "needs nginx + ModSecurity (run inside the shieldwaf image: tests/unit/run.sh)")
class Engine(unittest.TestCase):
    PORT, BACK = 18081, 18082

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        rules, cls.report = openapi.compile_rules(json.dumps(SPEC), "enforce", True, "deny", max_body_kb=2, max_depth=10)
        cls.rules = rules
        open(f"{cls.dir}/api.conf", "w").write("SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 1048576\nSecRequestBodyJsonDepthLimit 512\nSecArgumentsLimit 1000\n"
                                               "SecResponseBodyAccess Off\nSecTmpDir /tmp\nSecDataDir /tmp\nSecAuditEngine Off\n" + rules)
        open(f"{cls.dir}/nginx.conf", "w").write(f"""load_module {MODSEC};
worker_processes 1; pid {cls.dir}/nginx.pid; error_log {cls.dir}/err.log warn;
events {{ worker_connections 64; }}
http {{ access_log off; client_body_temp_path {cls.dir}/cb; proxy_temp_path {cls.dir}/pt; fastcgi_temp_path {cls.dir}/fc; uwsgi_temp_path {cls.dir}/uw; scgi_temp_path {cls.dir}/sc;
  client_max_body_size 5m;
  modsecurity on; modsecurity_rules_file {cls.dir}/api.conf;
  server {{ listen {cls.PORT}; location / {{ proxy_pass http://127.0.0.1:{cls.BACK}; }} }} }}""")
        t = subprocess.run([NGINX, "-t", "-c", f"{cls.dir}/nginx.conf"], capture_output=True, text=True)
        if t.returncode != 0:
            raise RuntimeError("nginx -t failed: " + t.stderr[-800:])
        cls.back = http.server.ThreadingHTTPServer(("127.0.0.1", cls.BACK), Backend)
        threading.Thread(target=cls.back.serve_forever, daemon=True).start()
        cls.nginx = subprocess.Popen([NGINX, "-c", f"{cls.dir}/nginx.conf", "-g", "daemon off;"], stderr=subprocess.DEVNULL)
        time.sleep(2)

    @classmethod
    def tearDownClass(cls):
        cls.nginx.terminate()
        cls.back.shutdown()
        if os.environ.get("DEBUG_OPENAPI"):
            print(open(f"{cls.dir}/err.log").read()[-6000:])

    def call(self, method, path, body=None, ctype="application/json", raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(f"http://127.0.0.1:{self.PORT}{path}", data=data, method=method, headers={"Content-Type": ctype} if data is not None else {})
        try:
            return urllib.request.urlopen(req, timeout=10).status
        except urllib.error.HTTPError as e:
            return e.code

    def order(self, **over):
        o = {"id": 7, "customer": {"name": "Ann"}, "items": [{"sku": "ABC-1234", "qty": 2}], "labels": ["a", "b"]}
        o.update(over)
        return o

    def check(self, want, body, msg=""):
        self.assertEqual(self.call("POST", "/orders", body), want, msg or json.dumps(body)[:120])

    # --- the valid request, and the basics
    def test_valid_order(self):
        self.check(200, self.order())

    def test_valid_order_with_everything(self):
        self.check(200, self.order(address={"city": "x"}, status="paid", ref="123e4567-e89b-12d3-a456-426614174000", score=5.5, tags=["a"], meta={"anything": {"goes": [1, 2]}},
                                   extended={"a": "1", "b": "2"}, customer={"name": "Ann", "email": "ann@example.com"}))

    def test_missing_required_top_level_fields(self):
        for k in ("id", "customer"):
            o = self.order()
            del o[k]
            self.check(400, o, "missing " + k)

    # --- types and ranges
    def test_integer_rules(self):
        for bad in ("abc", 0, -5, 1000001, "1.5", ""):
            self.check(400, self.order(id=bad), f"id={bad!r}")

    def test_exclusive_bounds(self):
        for bad in (0, 10, -1, 11):
            self.check(400, self.order(score=bad), f"score={bad}")
        self.check(200, self.order(score=9.99))

    def test_enum(self):
        self.check(400, self.order(status="hacked"))

    def test_formats(self):
        self.check(400, self.order(ref="not-a-uuid"))
        self.check(400, self.order(customer={"name": "Ann", "email": "not-an-email"}))

    def test_string_length(self):
        for bad in ("A", "A" * 21):
            self.check(400, self.order(customer={"name": bad}), f"name length {len(bad)}")

    # --- nested required properties
    def test_required_property_of_a_required_object(self):
        self.check(400, self.order(customer={"email": "a@example.com"}))

    def test_required_property_of_an_optional_object_only_when_the_object_is_present(self):
        self.check(400, self.order(address={"zip": "1"}), "address present without city")
        self.check(200, self.order(address={"city": "c"}))
        self.check(200, self.order(), "address absent is fine")

    def test_allof_is_merged(self):
        self.check(400, self.order(extended={"a": "1"}), "b missing")
        self.check(400, self.order(extended={"b": "1"}), "a missing")

    # --- arrays
    def test_required_properties_inside_array_items(self):
        base = [{"sku": "ABC-1234", "qty": 1}] * 5
        for idx in (0, 2, 4):
            items = [dict(x) for x in base]
            del items[idx]["qty"]
            self.check(400, self.order(items=items), f"item {idx} without qty")
        items = [dict(x) for x in base]
        del items[3]["sku"]
        self.check(400, self.order(items=items), "item 3 without sku")

    def test_values_inside_array_items(self):
        self.check(400, self.order(items=[{"sku": "ABC-1234", "qty": 0}]), "qty below minimum")
        self.check(400, self.order(items=[{"sku": "ABC-1234", "qty": 101}]), "qty above maximum")
        self.check(400, self.order(items=[{"sku": "abc-1234", "qty": 1}]), "sku pattern")
        self.check(400, self.order(items=[{"sku": "ABC-1234", "qty": 1}, {"sku": "bad", "qty": 1}]), "second item sku pattern")

    def test_max_items(self):
        self.check(200, self.order(items=[{"sku": "ABC-1234", "qty": 1}] * 5))
        self.check(400, self.order(items=[{"sku": "ABC-1234", "qty": 1}] * 6))

    def test_required_array_with_min_items(self):
        self.check(400, self.order(labels=["only-one"]), "fewer than minItems")
        self.check(400, self.order(labels=[]), "empty required array")
        o = self.order()
        del o["labels"]
        self.check(400, o, "missing required array")
        self.check(200, self.order(tags=[]), "an optional array may be empty")

    def test_unknown_field_and_additional_properties(self):
        self.check(400, self.order(admin=True), "unknown top-level field")
        self.check(400, self.order(customer={"name": "Ann", "role": "root"}), "unknown nested field")
        self.check(400, self.order(items=[{"sku": "ABC-1234", "qty": 1, "x": 1}]), "unknown field in an array item")

    # --- size and depth
    def test_body_size_limit(self):
        self.check(413, self.order(meta={"pad": "x" * 3000}), "body over 2 KB")
        self.check(200, self.order(meta={"pad": "x" * 500}))

    def test_json_depth_limit(self):
        self.check(200, self.order(meta=deep(5)))
        self.check(400, self.order(meta=deep(14)), "nested deeper than the limit")

    def test_malicious_json_structures(self):
        self.assertEqual(self.call("POST", "/orders", raw=b"{" * 600), 400)                           # unbalanced, deeply nested
        self.assertIn(self.call("POST", "/orders", raw=b'{"id": 1, "id": 2, "customer": {"name": "Ann"}, "items": []}'), (200, 400))
        self.assertEqual(self.call("POST", "/orders", raw=b"not json"), 400)

    # --- content type, methods, paths, query
    def test_content_type(self):
        self.assertEqual(self.call("POST", "/orders", self.order(), ctype="text/plain"), 415)
        self.assertEqual(self.call("POST", "/orders", self.order(), ctype="application/x-www-form-urlencoded"), 415)

    def test_methods_and_paths(self):
        self.assertEqual(self.call("GET", "/orders"), 405)
        self.assertEqual(self.call("DELETE", "/orders/5"), 405)
        self.assertEqual(self.call("GET", "/orders/5"), 200)
        self.assertEqual(self.call("GET", "/orders/abc"), 404, "path parameter must be an integer")
        self.assertEqual(self.call("GET", "/nothing"), 404, "unknown path")

    def test_query_parameters(self):
        self.assertEqual(self.call("GET", "/orders/5?verbose=true"), 200)
        self.assertEqual(self.call("GET", "/orders/5?verbose=maybe"), 400)
        self.assertEqual(self.call("GET", "/orders/5?debug=1"), 400)


class Compiler(unittest.TestCase):
    """Compile-time behaviour: no engine needed."""

    def spec(self, schema, **extra):
        return json.dumps({"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {"/p": {"post": {"requestBody": {"required": True, "content": {"application/json": {"schema": schema}}}}}},
                           **extra})

    def test_report_names_what_is_not_enforced(self):
        _, rep = openapi.compile_rules(self.spec({"oneOf": [{"type": "string"}, {"type": "integer"}]}), "enforce")
        self.assertTrue(any("oneOf" in r for r in rep), rep)

    def test_unsafe_pattern_is_not_run_in_the_firewall(self):
        rules, rep = openapi.compile_rules(self.spec({"type": "object", "properties": {"a": {"type": "string", "pattern": "^(a+)+$"}}}), "enforce")
        self.assertNotIn("(a+)+", rules)
        self.assertTrue(any("pattern" in r and "not enforced" in r for r in rep), rep)

    def test_pattern_with_lookahead_or_backreference_is_refused(self):
        for p in ("^(?=a)a$", r"^(a)\1$", "x" * 300):
            self.assertFalse(openapi._safe_pattern(p), p)
        self.assertTrue(openapi._safe_pattern("^[A-Z]{3}-[0-9]{4}$"))

    def test_recursive_schema_is_bounded(self):
        spec = json.dumps({"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "components": {"schemas": {"Node": {"type": "object", "properties": {
            "child": {"$ref": "#/components/schemas/Node"}, "v": {"type": "string"}}}}},
            "paths": {"/p": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}}}}}})
        rules, rep = openapi.compile_rules(spec, "enforce")
        self.assertTrue(any("levels deep" in r for r in rep), rep)
        self.assertLess(len(rules), 200000)

    def test_reference_cycles_and_remote_references_are_refused(self):
        cyc = json.dumps({"openapi": "3.0.0", "info": {}, "components": {"schemas": {"A": {"$ref": "#/components/schemas/B"}, "B": {"$ref": "#/components/schemas/A"}}},
                          "paths": {"/p": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/A"}}}}}}}})
        with self.assertRaises(openapi.SpecError):
            openapi.compile_rules(cyc, "enforce")
        remote = self.spec({"$ref": "http://evil.example/schema.json"})
        with self.assertRaises(openapi.SpecError):
            openapi.compile_rules(remote, "enforce")
        with self.assertRaises(openapi.SpecError):
            openapi.compile_rules(self.spec({"$ref": "../../etc/passwd"}), "enforce")

    def test_huge_schema_hits_the_node_budget(self):
        props = {f"p{i}": {"type": "object", "properties": {f"q{j}": {"type": "string"} for j in range(20)}} for i in range(300)}
        with self.assertRaises(openapi.SpecError):
            openapi.compile_rules(self.spec({"type": "object", "properties": props}), "enforce")

    def test_hostile_documents(self):
        for text in ("[" * 5000, "{" * 5000, "", "null", "[]", '{"openapi": "2.0"}', '{"openapi": "3.0.0", "paths": {}}'):
            with self.assertRaises(openapi.SpecError, msg=text[:20]):
                openapi.compile_rules(text, "enforce")
        with self.assertRaises(openapi.SpecError):
            openapi.compile_rules(" " * (openapi.MAX_SPEC + 1), "enforce")

    def test_greater_than_regex_helper(self):
        import re
        for n in (0, 4, 9, 10, 24, 25, 99, 100, 250):
            rx = re.compile(r"^(?:" + openapi._gt_regex(n) + r")$")
            for v in range(0, 400):
                self.assertEqual(bool(rx.match(str(v))), v > n, (n, v))

    def test_rule_ids_are_unique(self):
        rules, _ = openapi.compile_rules(json.dumps(SPEC), "enforce")
        import re
        ids = re.findall(r"id:(\d+)", rules)
        self.assertEqual(len(ids), len(set(ids)))

    def test_body_limit_and_depth_parameters_are_clamped(self):
        rules, _ = openapi.compile_rules(json.dumps(SPEC), "enforce", max_body_kb=-5, max_depth=1000)
        self.assertIn("@gt 1024", rules)                                           # 1 KB minimum
        rules, _ = openapi.compile_rules(json.dumps(SPEC), "enforce", max_body_kb=10 ** 9)
        self.assertIn(f"@gt {1024 * 1024 * 1024}", rules)


if __name__ == "__main__":
    unittest.main(verbosity=2)
