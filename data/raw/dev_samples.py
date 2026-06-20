"""
Exemplos de desenvolvimento para testar o pipeline antes do dataset completo.
Cada entrada tem um diff realista e um rótulo:
  1 = precisa de revisão de segurança (high/medium)
  0 = revisão normal (low)

Fonte: construídos manualmente a partir de padrões comuns em commits públicos.
Não usar para reportar métricas reais de desempenho.
"""

SAMPLES: list[dict] = [
    # ── LABEL 1: alto risco ──────────────────────────────────────────────────
    {
        "id": "auth_verify_disabled",
        "label": 1,
        "diff": """\
diff --git a/src/auth/client.py b/src/auth/client.py
--- a/src/auth/client.py
+++ b/src/auth/client.py
@@ -12,7 +12,7 @@
 def get_session(url):
-    response = requests.get(url, verify=True)
+    response = requests.get(url, verify=False)
     return response
""",
    },
    {
        "id": "hardcoded_secret",
        "label": 1,
        "diff": """\
diff --git a/config/settings.py b/config/settings.py
--- a/config/settings.py
+++ b/config/settings.py
@@ -5,3 +5,4 @@
 DEBUG = False
+API_KEY = "sk-prod-abc123secret"
+CLIENT_SECRET = "super_secret_value_here"
""",
    },
    {
        "id": "sql_string_concat",
        "label": 1,
        "diff": """\
diff --git a/app/db/queries.py b/app/db/queries.py
--- a/app/db/queries.py
+++ b/app/db/queries.py
@@ -8,5 +8,5 @@
 def get_user(username):
-    query = "SELECT * FROM users WHERE name = %s"
-    return db.execute(query, (username,))
+    query = "SELECT * FROM users WHERE name = '" + username + "'"
+    return db.execute(query)
""",
    },
    {
        "id": "cors_open",
        "label": 1,
        "diff": """\
diff --git a/server/middleware.js b/server/middleware.js
--- a/server/middleware.js
+++ b/server/middleware.js
@@ -3,4 +3,4 @@
-app.use(cors({ origin: "https://trusted.example.com" }));
+app.use(cors());
""",
    },
    {
        "id": "eval_user_input",
        "label": 1,
        "diff": """\
diff --git a/api/handlers.py b/api/handlers.py
--- a/api/handlers.py
+++ b/api/handlers.py
@@ -10,4 +10,5 @@
 def process(request):
     data = request.json()
-    result = safe_eval(data["expr"])
+    result = eval(data["expr"])
     return result
""",
    },
    {
        "id": "jwt_none_algorithm",
        "label": 1,
        "diff": """\
diff --git a/src/auth/tokens.py b/src/auth/tokens.py
--- a/src/auth/tokens.py
+++ b/src/auth/tokens.py
@@ -6,5 +6,5 @@
 def decode_token(token):
-    return jwt.decode(token, SECRET, algorithms=["HS256"])
+    return jwt.decode(token, options={"verify_signature": False})
""",
    },
    {
        "id": "csrf_disabled",
        "label": 1,
        "diff": """\
diff --git a/app/settings.py b/app/settings.py
--- a/app/settings.py
+++ b/app/settings.py
@@ -20,4 +20,4 @@
 MIDDLEWARE = [
-    "django.middleware.csrf.CsrfViewMiddleware",
+    # disable csrf for development
""",
    },
    {
        "id": "subprocess_user_input",
        "label": 1,
        "diff": """\
diff --git a/utils/runner.py b/utils/runner.py
--- a/utils/runner.py
+++ b/utils/runner.py
@@ -4,4 +4,5 @@
 import subprocess
 def run_report(name):
-    subprocess.run(["report-tool", "--name", name], check=True)
+    subprocess.run(f"report-tool --name {name}", shell=True, check=True)
""",
    },
    {
        "id": "crypto_weak_hash",
        "label": 1,
        "diff": """\
diff --git a/auth/password.py b/auth/password.py
--- a/auth/password.py
+++ b/auth/password.py
@@ -2,4 +2,5 @@
 import hashlib
 def hash_password(pw):
-    return hashlib.sha256(pw.encode()).hexdigest()
+    return hashlib.md5(pw.encode()).hexdigest()
""",
    },
    {
        "id": "private_key_committed",
        "label": 1,
        "diff": """\
diff --git a/deploy/server.key b/deploy/server.key
new file mode 100644
--- /dev/null
+++ b/deploy/server.key
@@ -0,0 +1,5 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJx9EkZTsGGbIIVBrFOsDqKHAN8=
+...
+-----END RSA PRIVATE KEY-----
""",
    },
    {
        "id": "rbac_bypass",
        "label": 1,
        "diff": """\
diff --git a/api/views.py b/api/views.py
--- a/api/views.py
+++ b/api/views.py
@@ -8,5 +8,4 @@
-@require_permission("admin")
 def delete_user(request, user_id):
     User.objects.filter(id=user_id).delete()
""",
    },
    {
        "id": "deserialization_unsafe",
        "label": 1,
        "diff": """\
diff --git a/app/cache.py b/app/cache.py
--- a/app/cache.py
+++ b/app/cache.py
@@ -3,4 +3,5 @@
 import pickle
 def load_cache(data):
-    return json.loads(data)
+    return pickle.loads(data)
""",
    },
    {
        "id": "terraform_public_bucket",
        "label": 1,
        "diff": """\
diff --git a/infra/storage.tf b/infra/storage.tf
--- a/infra/storage.tf
+++ b/infra/storage.tf
@@ -5,4 +5,4 @@
 resource "aws_s3_bucket_acl" "data" {
-  acl = "private"
+  acl = "public-read"
 }
""",
    },
    {
        "id": "dependency_vuln_added",
        "label": 1,
        "diff": """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -3,3 +3,4 @@
 flask==2.0.1
+pyyaml==5.1
+requests==2.18.0
""",
    },
    # ── LABEL 0: revisão normal ───────────────────────────────────────────────
    {
        "id": "readme_update",
        "label": 0,
        "diff": """\
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,3 +1,5 @@
 # Project
+
+## Installation
+Run `pip install -e .` to install in editable mode.
""",
    },
    {
        "id": "test_added",
        "label": 0,
        "diff": """\
diff --git a/tests/test_parser.py b/tests/test_parser.py
new file mode 100644
--- /dev/null
+++ b/tests/test_parser.py
@@ -0,0 +1,12 @@
+import unittest
+from parser import parse
+
+class TestParser(unittest.TestCase):
+    def test_empty(self):
+        self.assertEqual(parse(""), [])
+
+    def test_basic(self):
+        result = parse("hello world")
+        self.assertEqual(len(result), 2)
""",
    },
    {
        "id": "style_refactor",
        "label": 0,
        "diff": """\
diff --git a/app/utils.py b/app/utils.py
--- a/app/utils.py
+++ b/app/utils.py
@@ -10,8 +10,5 @@
 def format_name(first, last):
-    name = first
-    name = name + " "
-    name = name + last
-    return name
+    return f"{first} {last}"
""",
    },
    {
        "id": "logging_added",
        "label": 0,
        "diff": """\
diff --git a/app/orders.py b/app/orders.py
--- a/app/orders.py
+++ b/app/orders.py
@@ -5,4 +5,6 @@
 def process_order(order_id):
     order = Order.objects.get(id=order_id)
+    logger.info("Processing order %s", order_id)
     order.process()
+    logger.info("Order %s done", order_id)
""",
    },
    {
        "id": "comment_removed",
        "label": 0,
        "diff": """\
diff --git a/lib/helpers.py b/lib/helpers.py
--- a/lib/helpers.py
+++ b/lib/helpers.py
@@ -3,5 +3,3 @@
 def calculate_total(items):
-    # TODO: add tax
-    # TODO: add discount
     return sum(item.price for item in items)
""",
    },
    {
        "id": "pagination_feature",
        "label": 0,
        "diff": """\
diff --git a/api/list_view.py b/api/list_view.py
--- a/api/list_view.py
+++ b/api/list_view.py
@@ -8,4 +8,7 @@
 def list_items(request):
-    items = Item.objects.all()
-    return JsonResponse({"items": list(items.values())})
+    page = int(request.GET.get("page", 1))
+    per_page = 20
+    start = (page - 1) * per_page
+    items = Item.objects.all()[start:start + per_page]
+    return JsonResponse({"items": list(items.values()), "page": page})
""",
    },
    {
        "id": "typo_fix",
        "label": 0,
        "diff": """\
diff --git a/docs/api.md b/docs/api.md
--- a/docs/api.md
+++ b/docs/api.md
@@ -10,3 +10,3 @@
-Returns the the list of users.
+Returns the list of users.
""",
    },
    {
        "id": "ci_timeout_bump",
        "label": 0,
        "diff": """\
diff --git a/.github/workflows/test.yml b/.github/workflows/test.yml
--- a/.github/workflows/test.yml
+++ b/.github/workflows/test.yml
@@ -12,3 +12,3 @@
-      timeout-minutes: 10
+      timeout-minutes: 20
""",
    },
    {
        "id": "dependency_pin",
        "label": 0,
        "diff": """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,3 +1,3 @@
-flask>=2.0
+flask==2.3.3
""",
    },
    {
        "id": "error_message_improved",
        "label": 0,
        "diff": """\
diff --git a/api/errors.py b/api/errors.py
--- a/api/errors.py
+++ b/api/errors.py
@@ -5,4 +5,4 @@
 def not_found(e):
-    return jsonify({"error": "not found"}), 404
+    return jsonify({"error": "Resource not found", "code": 404}), 404
""",
    },
    {
        "id": "model_field_added",
        "label": 0,
        "diff": """\
diff --git a/models/product.py b/models/product.py
--- a/models/product.py
+++ b/models/product.py
@@ -8,4 +8,5 @@
 class Product(Base):
     id = Column(Integer, primary_key=True)
     name = Column(String(200))
+    description = Column(Text, nullable=True)
""",
    },
]
