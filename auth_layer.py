# -*- coding: utf-8 -*-

import os
import json
import time
import asyncio
import hashlib
import secrets
import contextvars
from datetime import datetime, timedelta
from typing import Dict, Any, List

from aiohttp import web

import dashboard_server as ds

bot_state = ds.bot_state

from templates import (
    LOGIN_HTML,
    PLANS_HTML,
    DASHBOARD_HTML,
    EXPIRED_HTML,
    ADMIN_LOGIN_HTML,
    ADMIN_PANEL_HTML,
    HOME_HTML,
)

ADMIN_USERNAME = "malakar"
ADMIN_PASSWORD = "mukesh"
ADMIN_PATH = "/admin/mukesh/levelup/adm-dash"

DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")

SESSION_COOKIE = "vxl_session"
SESSION_TTL = 7 * 24 * 3600

EXP_DAILY_LIMIT = 49000
DAILY_RESET_HOUR = 4
MAX_SLOTS_LIMIT = 500
BULK_CHECK_CONCURRENCY = 8

USER_WORKERS: Dict[str, Dict[str, asyncio.Task]] = {}
USER_PAUSED: Dict[str, set] = {}
USER_DELETED: Dict[str, set] = {}
USER_DAILY_LIMIT_HIT: Dict[str, set] = {}
USER_TARGET_HIT: Dict[str, set] = {}
USER_ACTIVE_BATCH: Dict[str, set] = {}
_LAST_SYNC: Dict[str, float] = {}
_CURRENT_OWNER = contextvars.ContextVar("current_owner", default=None)


# ============================================================
# HELPERS
# ============================================================

def _seconds_until_4am():
    now = datetime.now()
    next_4am = now.replace(hour=DAILY_RESET_HOUR, minute=0, second=0, microsecond=0)
    if now >= next_4am:
        next_4am += timedelta(days=1)
    return (next_4am - now).total_seconds()


def _today_key():
    now = datetime.now()
    if now.hour < DAILY_RESET_HOUR:
        now = now - timedelta(days=1)
    return now.strftime("%Y-%m-%d")


def _get_real_id_for_key(username: str, key_str: str, acc_type: str = "guest"):
    try:
        for live_uid, cred in list(ds.bot_state.account_credentials.items()):
            if acc_type == "guest":
                if str(cred.get("auth_uid", "")) == key_str:
                    return str(live_uid)
            elif acc_type == "token":
                if str(cred.get("auth_token", ""))[:20] == key_str:
                    return str(live_uid)
    except Exception:
        pass
    return None


async def sync_user_accounts_to_disk(username):
    try:
        users = load_users()
        u = users.get(username)
        if not u:
            return
        accounts = u.get("accounts", [])
        if not accounts:
            return
        changed = False
        for saved in accounts:
            saved_key = str(saved.get("uid")) if saved.get("type") == "guest" else str(saved.get("token", ""))[:20]
            live = None
            for uid, acc in ds.bot_state.accounts.items():
                if acc.get("_owner") != username:
                    continue
                if str(uid) == saved_key:
                    live = acc
                    break
                cred = ds.bot_state.account_credentials.get(str(uid))
                if cred:
                    if saved.get("type") == "guest" and str(cred.get("auth_uid", "")) == saved_key:
                        live = acc
                        break
                    if saved.get("type") == "token" and str(cred.get("auth_token", ""))[:20] == saved_key:
                        live = acc
                        break
            if not live:
                continue
            real_id = str(live.get("uid") or live.get("account_id") or "")
            if real_id and saved.get("real_account_id") != real_id:
                saved["real_account_id"] = real_id
                changed = True
            if saved.get("initial_exp") is None and live.get("initial_exp") is not None:
                saved["initial_exp"] = live["initial_exp"]
                changed = True
            new_last_exp = live.get("current_exp")
            if new_last_exp is not None and saved.get("last_exp") != new_last_exp:
                saved["last_exp"] = new_last_exp
                changed = True
            new_level = live.get("level")
            if new_level is not None and saved.get("last_level") != new_level:
                saved["last_level"] = new_level
                changed = True
            new_nick = live.get("nickname")
            if new_nick and saved.get("last_nickname") != new_nick:
                saved["last_nickname"] = new_nick
                changed = True
            new_region = live.get("region")
            if new_region and saved.get("last_region") != new_region:
                saved["last_region"] = new_region
                changed = True
            new_gained = live.get("gained_exp")
            if new_gained is not None and saved.get("gained_exp") != new_gained:
                saved["gained_exp"] = new_gained
                changed = True
            new_played = live.get("matches_played")
            if new_played is not None and saved.get("matches_played") != new_played:
                saved["matches_played"] = new_played
                changed = True
            if live.get("created_at") and saved.get("created_at") != live.get("created_at"):
                saved["created_at"] = live.get("created_at")
                changed = True
            saved["last_update"] = time.time()
            changed = True
        if changed:
            save_users(users)
    except Exception as e:
        print(f"[auth] sync error for {username}: {e}", flush=True)


def _ensure():
    os.makedirs(DATA_DIR, exist_ok=True)


def _read(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _write(path, data):
    _ensure()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def load_users():
    return _read(USERS_FILE, {})


def save_users(u):
    _write(USERS_FILE, u)


def load_sessions():
    return _read(SESSIONS_FILE, {})


def save_sessions(s):
    _write(SESSIONS_FILE, s)


def hash_pw(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120000)
    return h.hex(), salt


def verify_pw(pw, h, salt):
    hh, _ = hash_pw(pw, salt)
    return secrets.compare_digest(hh, h)


def create_session(username, is_admin=False):
    token = secrets.token_urlsafe(32)
    s = load_sessions()
    now = time.time()
    s[token] = {"username": username, "is_admin": is_admin, "created_at": now, "expires_at": now + SESSION_TTL}
    now_ts = time.time()
    s = {k: v for k, v in s.items() if v.get("expires_at", 0) > now_ts}
    save_sessions(s)
    return token


def get_session(token):
    if not token:
        return None
    s = load_sessions()
    v = s.get(token)
    if not v:
        return None
    if time.time() > v.get("expires_at", 0):
        s.pop(token, None)
        save_sessions(s)
        return None
    return v


def destroy_session(token):
    s = load_sessions()
    s.pop(token, None)
    save_sessions(s)


def cur_user(req):
    return get_session(req.cookies.get(SESSION_COOKIE))


def cur_admin(req):
    s = cur_user(req)
    if s and s.get("is_admin"):
        return s
    return None


def _set_ck(resp, token):
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="Lax", path="/")


def _clr_ck(resp):
    resp.del_cookie(SESSION_COOKIE, path="/")


def check_daily_limit(uid: str, gained_exp: int) -> bool:
    return gained_exp >= EXP_DAILY_LIMIT


def should_restart_worker(username: str, uid: str) -> bool:
    today = _today_key()
    users = load_users()
    u = users.get(username, {})
    for acc in u.get("accounts", []):
        key = str(acc.get("uid")) if acc.get("type") == "guest" else str(acc.get("token", ""))[:20]
        if key == uid:
            last_reset = acc.get("last_reset_date", "")
            if last_reset != today:
                acc["last_reset_date"] = today
                acc["daily_gained_exp"] = 0
                save_users(users)
                return True
    return False


# ============================================================
# PATCHED REGISTER
# ============================================================

_orig_register = ds.BotState.register_account


def _patched_register(self, uid, nickname, region, level, exp, likes=0):
    uid_str = str(uid)
    owner = _CURRENT_OWNER.get()

    if owner is None:
        try:
            for un, udata in load_users().items():
                for acc in udata.get("accounts", []):
                    if acc.get("type") == "guest":
                        acc_uid = str(acc.get("uid", ""))
                    else:
                        acc_uid = str(acc.get("token", ""))[:20]
                    if acc_uid == uid_str:
                        owner = un
                        break
                if owner:
                    break
        except Exception:
            pass

    if owner:
        deleted = USER_DELETED.get(owner, set())
        paused = USER_PAUSED.get(owner, set())
        if uid_str in deleted or uid_str in paused:
            return

    saved_initial = None
    saved_matches = 0
    saved_created = None
    if owner:
        try:
            users = load_users()
            u = users.get(owner)
            if u:
                for saved in u.get("accounts", []):
                    saved_key = str(saved.get("uid")) if saved.get("type") == "guest" else str(saved.get("token", ""))[:20]
                    if saved_key == uid_str:
                        saved_initial = saved.get("initial_exp")
                        saved_matches = saved.get("matches_played", 0)
                        saved_created = saved.get("created_at")
                        break
        except Exception:
            pass

    is_new = uid_str not in self.accounts
    _orig_register(self, uid, nickname, region, level, exp, likes)
    acc = self.accounts.get(uid_str)
    if not acc:
        return

    if saved_initial is not None:
        acc["initial_exp"] = saved_initial
        acc["gained_exp"] = max(0, exp - saved_initial)
    if saved_matches > 0:
        acc["matches_played"] = saved_matches
    if saved_created:
        acc["created_at"] = saved_created

    if owner:
        acc["_owner"] = owner

    if is_new and "created_at" not in acc:
        acc["created_at"] = time.time()

    acc["last_update"] = time.time()

    if owner:
        try:
            users = load_users()
            u = users.get(owner)
            if u:
                for saved in u.get("accounts", []):
                    saved_key = str(saved.get("uid")) if saved.get("type") == "guest" else str(saved.get("token", ""))[:20]
                    if saved_key == uid_str:
                        if saved.get("initial_exp") is None:
                            saved["initial_exp"] = acc["initial_exp"]
                        saved["last_exp"] = acc["current_exp"]
                        saved["last_level"] = acc["level"]
                        saved["last_nickname"] = acc["nickname"]
                        saved["last_region"] = acc["region"]
                        saved["gained_exp"] = acc["gained_exp"]
                        saved["matches_played"] = acc["matches_played"]
                        saved["created_at"] = acc.get("created_at")
                        saved["last_update"] = time.time()
                        saved["real_account_id"] = uid_str
                        break
                save_users(users)
        except Exception:
            pass


ds.BotState.register_account = _patched_register


# ============================================================
# WORKER MANAGEMENT
# ============================================================

async def stop_user_workers(username):
    workers = USER_WORKERS.pop(username, {})
    tasks = list(workers.values())
    for t in tasks:
        if not t.done():
            t.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    for key in list(bot_state.account_workers.keys()):
        if str(key).startswith(username + "::"):
            t = bot_state.account_workers.pop(key, None)
            if t and not t.done():
                t.cancel()
            if t:
                try:
                    await asyncio.wait_for(t, timeout=3)
                except Exception:
                    pass

    await asyncio.sleep(0.2)


async def start_user_workers(username):
    users = load_users()
    u = users.get(username)
    if not u:
        return
    if time.time() >= u.get("expires_at", 0):
        return

    if username not in USER_WORKERS:
        USER_WORKERS[username] = {}
    if username not in USER_PAUSED:
        USER_PAUSED[username] = set()
    if username not in USER_DELETED:
        USER_DELETED[username] = set()
    if username not in USER_DAILY_LIMIT_HIT:
        USER_DAILY_LIMIT_HIT[username] = set()
    if username not in USER_TARGET_HIT:
        USER_TARGET_HIT[username] = set()
    if username not in USER_ACTIVE_BATCH:
        USER_ACTIVE_BATCH[username] = set()

    workers = USER_WORKERS[username]
    paused = USER_PAUSED[username]
    deleted = USER_DELETED[username]
    daily_hit = USER_DAILY_LIMIT_HIT[username]
    target_hit = USER_TARGET_HIT[username]
    active_batch = USER_ACTIVE_BATCH[username]

    today = _today_key()
    changed = False

    auto_split = u.get("auto_split", False)
    target_level = int(u.get("target_level", 0) or 0)
    one_time_run = int(u.get("one_time_run", 0) or 0)

    for acc in u.get("accounts", []):
        key = acc.get("uid") if acc.get("type") == "guest" else acc.get("token", "")[:20]
        if not key:
            continue
        if key in paused or key in deleted or key in target_hit:
            continue
        if key in daily_hit:
            continue
        if key in workers and not workers[key].done():
            continue

        last_reset = acc.get("last_reset_date", "")
        if last_reset != today:
            acc["last_reset_date"] = today
            acc["daily_gained_exp"] = 0
            daily_hit.discard(key)
            changed = True

        if auto_split:
            cur_lvl = int(acc.get("last_level", 0) or 0)
            if target_level > 0 and cur_lvl >= target_level:
                target_hit.add(key)
                paused.add(key)
                changed = True
                continue
            if one_time_run > 0 and key not in active_batch:
                if len(active_batch) >= one_time_run:
                    continue
                active_batch.add(key)
                changed = True

        if acc.get("type") == "guest":
            t = asyncio.create_task(_guest_worker(username, acc["uid"], acc["password"]))
        else:
            t = asyncio.create_task(_token_worker(username, acc["token"]))
        workers[key] = t
        bot_state.account_workers[username + "::" + key] = t

    if changed:
        save_users(users)


async def _guest_worker(username, uid, password):
    try:
        import main as m
    except Exception as e:
        print(f"[auth] Cannot import main: {e}", flush=True)
        return
    while True:
        try:
            if uid in USER_DELETED.get(username, set()):
                break
            if uid in USER_PAUSED.get(username, set()):
                break
            if uid in USER_TARGET_HIT.get(username, set()):
                break

            if uid in USER_DAILY_LIMIT_HIT.get(username, set()):
                wait_secs = _seconds_until_4am()
                print(f"[auth] Guest {uid} daily limit hit -> waiting {wait_secs:.0f}s", flush=True)
                while wait_secs > 0:
                    if uid in USER_DELETED.get(username, set()) or uid in USER_PAUSED.get(username, set()) or uid in USER_TARGET_HIT.get(username, set()):
                        break
                    chunk = min(wait_secs, 60)
                    await asyncio.sleep(chunk)
                    wait_secs -= chunk
                if should_restart_worker(username, uid):
                    USER_DAILY_LIMIT_HIT.get(username, set()).discard(uid)
                    users = load_users()
                    u = users.get(username, {})
                    for acc in u.get("accounts", []):
                        acc_key = str(acc.get("uid")) if acc.get("type") == "guest" else str(acc.get("token", ""))[:20]
                        if acc_key == uid:
                            acc["initial_exp"] = None
                            acc["gained_exp"] = 0
                            acc["daily_gained_exp"] = 0
                            save_users(users)
                            break
                else:
                    continue

            cv = _CURRENT_OWNER.set(username)
            try:
                ad = await m.process_account_uid_pass(uid, password)
                if not ad:
                    await asyncio.sleep(15)
                    continue
                acc_id = str(ad.get("account_id", ""))
                if uid in USER_DELETED.get(username, set()) or acc_id in USER_DELETED.get(username, set()):
                    break
                if uid in USER_PAUSED.get(username, set()) or acc_id in USER_PAUSED.get(username, set()):
                    break
                if uid in USER_TARGET_HIT.get(username, set()) or acc_id in USER_TARGET_HIT.get(username, set()):
                    break
                await m.run_account_worker(ad, uid)
                if uid in USER_DELETED.get(username, set()) or acc_id in USER_DELETED.get(username, set()):
                    break
                if uid in USER_TARGET_HIT.get(username, set()) or acc_id in USER_TARGET_HIT.get(username, set()):
                    break
                if uid in USER_DAILY_LIMIT_HIT.get(username, set()):
                    continue
                # Auto-split rotation check
                users = load_users()
                u = users.get(username, {})
                if u.get("auto_split"):
                    asyncio.create_task(_rotate_batch(username))
                await asyncio.sleep(3)
            finally:
                _CURRENT_OWNER.reset(cv)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[auth] Guest worker error {uid}: {type(e).__name__}: {e}", flush=True)
            await asyncio.sleep(10)


async def _token_worker(username, token):
    try:
        import main as m
    except Exception as e:
        print(f"[auth] Cannot import main: {e}", flush=True)
        return
    while True:
        try:
            key = token[:20]
            if key in USER_DELETED.get(username, set()):
                break
            if key in USER_PAUSED.get(username, set()):
                break
            if key in USER_TARGET_HIT.get(username, set()):
                break

            if key in USER_DAILY_LIMIT_HIT.get(username, set()):
                wait_secs = _seconds_until_4am()
                print(f"[auth] Token {key} daily limit hit -> waiting {wait_secs:.0f}s", flush=True)
                while wait_secs > 0:
                    if key in USER_DELETED.get(username, set()) or key in USER_PAUSED.get(username, set()) or key in USER_TARGET_HIT.get(username, set()):
                        break
                    chunk = min(wait_secs, 60)
                    await asyncio.sleep(chunk)
                    wait_secs -= chunk
                if should_restart_worker(username, key):
                    USER_DAILY_LIMIT_HIT.get(username, set()).discard(key)
                    users = load_users()
                    u = users.get(username, {})
                    for acc in u.get("accounts", []):
                        acc_key = str(acc.get("uid")) if acc.get("type") == "guest" else str(acc.get("token", ""))[:20]
                        if acc_key == key:
                            acc["initial_exp"] = None
                            acc["gained_exp"] = 0
                            acc["daily_gained_exp"] = 0
                            save_users(users)
                            break
                else:
                    continue

            cv = _CURRENT_OWNER.set(username)
            try:
                ad = await m.process_account_token(token)
                if not ad:
                    await asyncio.sleep(15)
                    continue
                acc_id = str(ad.get("account_id", ""))
                if key in USER_DELETED.get(username, set()) or acc_id in USER_DELETED.get(username, set()):
                    break
                if key in USER_PAUSED.get(username, set()) or acc_id in USER_PAUSED.get(username, set()):
                    break
                if key in USER_TARGET_HIT.get(username, set()) or acc_id in USER_TARGET_HIT.get(username, set()):
                    break
                await m.run_account_worker(ad, acc_id)
                if key in USER_DELETED.get(username, set()) or acc_id in USER_DELETED.get(username, set()):
                    break
                if key in USER_TARGET_HIT.get(username, set()) or acc_id in USER_TARGET_HIT.get(username, set()):
                    break
                if key in USER_DAILY_LIMIT_HIT.get(username, set()):
                    continue
                users = load_users()
                u = users.get(username, {})
                if u.get("auto_split"):
                    asyncio.create_task(_rotate_batch(username))
                await asyncio.sleep(3)
            finally:
                _CURRENT_OWNER.reset(cv)
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[auth] Token worker error {token[:10]}: {type(e).__name__}: {e}", flush=True)
            await asyncio.sleep(10)


async def _rotate_batch(username):
    """Auto-split: jab ek batch complete ho, next batch on karo."""
    try:
        users = load_users()
        u = users.get(username, {})
        if not u:
            return
        if not u.get("auto_split"):
            return
        target_level = int(u.get("target_level", 0) or 0)
        one_time_run = int(u.get("one_time_run", 0) or 0)

        if username not in USER_TARGET_HIT:
            USER_TARGET_HIT[username] = set()
        if username not in USER_ACTIVE_BATCH:
            USER_ACTIVE_BATCH[username] = set()
        if username not in USER_PAUSED:
            USER_PAUSED[username] = set()

        target_hit = USER_TARGET_HIT[username]
        active_batch = USER_ACTIVE_BATCH[username]
        paused = USER_PAUSED[username]

        # Check karo kitne active hain jo abhi tak running hain
        any_running = False
        for acc in u.get("accounts", []):
            key = acc.get("uid") if acc.get("type") == "guest" else acc.get("token", "")[:20]
            if not key:
                continue
            if key in target_hit:
                continue
            if key in active_batch:
                cur_lvl = int(acc.get("last_level", 0) or 0)
                if target_level > 0 and cur_lvl >= target_level:
                    target_hit.add(key)
                    paused.add(key)
                    active_batch.discard(key)
                    workers = USER_WORKERS.get(username, {})
                    t = workers.get(key)
                    if t and not t.done():
                        t.cancel()
                    print(f"[auto-split] Target hit: {key} (level {cur_lvl}) -> paused", flush=True)
                    continue
                any_running = True

        # Daily limit check bhi
        daily_hit = USER_DAILY_LIMIT_HIT.get(username, set())
        for k in list(active_batch):
            if k in daily_hit:
                active_batch.discard(k)

        if any_running:
            return

        # Batch complete — next batch on karo
        if len(active_batch) == 0:
            count = 0
            for acc in u.get("accounts", []):
                key = acc.get("uid") if acc.get("type") == "guest" else acc.get("token", "")[:20]
                if not key:
                    continue
                if key in target_hit or key in paused:
                    continue
                if key in USER_DAILY_LIMIT_HIT.get(username, set()):
                    continue
                active_batch.add(key)
                count += 1
                if one_time_run > 0 and count >= one_time_run:
                    break
            if count > 0:
                print(f"[auto-split] Next batch for {username}: {count} accounts activated", flush=True)
                asyncio.create_task(start_user_workers(username))
    except Exception as e:
        print(f"[auth] _rotate_batch error: {e}", flush=True)


# ============================================================
# PAGE HANDLERS
# ============================================================

async def h_root(req):
    return web.Response(text=HOME_HTML, content_type="text/html")


async def h_login_get(req):
    s = cur_user(req)
    if s and not s.get("is_admin"):
        raise web.HTTPFound("/dashboard")
    return web.Response(text=LOGIN_HTML, content_type="text/html")


async def h_login_post(req):
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    u = (d.get("username") or "").strip()
    p = d.get("password") or ""
    if not u or not p:
        return web.json_response({"status": "error", "error": "Missing Credentials"})
    users = load_users()
    x = users.get(u)
    if not x:
        return web.json_response({"status": "error", "error": "Invalid Credentials"})
    if not verify_pw(p, x.get("password_hash", ""), x.get("salt", "")):
        return web.json_response({"status": "error", "error": "Invalid Credentials"})
    token = create_session(u, False)
    print(f"[auth] Login OK user={u}", flush=True)
    resp = web.json_response({"status": "ok", "redirect": "/dashboard"})
    _set_ck(resp, token)
    if time.time() < x.get("expires_at", 0):
        asyncio.create_task(start_user_workers(u))
    return resp


async def h_signup(req):
    raise web.HTTPFound("/plans")


async def h_plans(req):
    s = cur_user(req)
    un = s["username"] if s else "{{USERNAME}}"
    return web.Response(text=PLANS_HTML.replace("{{USERNAME}}", un), content_type="text/html")


async def h_logout(req):
    token = req.cookies.get(SESSION_COOKIE)
    if token:
        s = get_session(token)
        if s and not s.get("is_admin"):
            await sync_user_accounts_to_disk(s["username"])
        destroy_session(token)
    r = web.HTTPFound("/login")
    _clr_ck(r)
    raise r


async def h_dash(req):
    s = cur_user(req)
    if not s or s.get("is_admin"):
        raise web.HTTPFound("/login")
    users = load_users()
    x = users.get(s["username"])
    if not x:
        raise web.HTTPFound("/logout")
    if time.time() >= x.get("expires_at", 0):
        raise web.HTTPFound("/expired")
    return web.Response(text=DASHBOARD_HTML.replace("{{USERNAME}}", s["username"]), content_type="text/html")


async def h_expired(req):
    s = cur_user(req)
    if not s or s.get("is_admin"):
        raise web.HTTPFound("/login")
    return web.Response(text=EXPIRED_HTML, content_type="text/html")


# ============================================================
# STATS
# ============================================================

async def h_stats(req):
    s = cur_user(req)
    if not s or s.get("is_admin"):
        return web.json_response({"error": "unauthorized"}, status=401)
    un = s["username"]
    users = load_users()
    u = users.get(un, {})
    now = time.time()
    exp_at = u.get("expires_at", 0)
    expired = now >= exp_at
    left = max(0, int(exp_at - now))
    paused = USER_PAUSED.get(un, set())
    deleted = USER_DELETED.get(un, set())
    daily_hit = USER_DAILY_LIMIT_HIT.get(un, set())
    target_hit = USER_TARGET_HIT.get(un, set())

    last_sync = _LAST_SYNC.get(un, 0)
    if now - last_sync > 30:
        _LAST_SYNC[un] = now
        asyncio.create_task(sync_user_accounts_to_disk(un))

    if not expired and un not in USER_WORKERS:
        asyncio.create_task(start_user_workers(un))

    out = []
    seen_real_ids = set()
    auto_split = u.get("auto_split", False)
    target_level = int(u.get("target_level", 0) or 0)

    # Auto-split rotation check
    if auto_split and not expired:
        asyncio.create_task(_rotate_batch(un))

    for uid, a in list(ds.bot_state.accounts.items()):
        if a.get("_owner") != un:
            continue
        if uid in deleted:
            continue
        real_id = str(uid)
        if real_id in seen_real_ids:
            continue
        seen_real_ids.add(real_id)

        gained = a.get("gained_exp", 0)
        if gained >= EXP_DAILY_LIMIT:
            if un not in USER_DAILY_LIMIT_HIT:
                USER_DAILY_LIMIT_HIT[un] = set()
            USER_DAILY_LIMIT_HIT[un].add(real_id)
            daily_hit = USER_DAILY_LIMIT_HIT[un]
            workers = USER_WORKERS.get(un, {})
            t = workers.get(real_id)
            if t and not t.done():
                t.cancel()

        is_paused = real_id in paused
        is_limit_hit = real_id in daily_hit
        is_target_hit = real_id in target_hit

        if is_target_hit:
            status = "TARGET_DONE"
        elif is_limit_hit:
            status = "DAILY_LIMIT"
        elif is_paused:
            status = "PAUSED"
        else:
            status = a.get("status", "LIVE")

        out.append({
            "uid": real_id,
            "nickname": a.get("nickname", "?"),
            "region": a.get("region", "IND"),
            "level": a.get("level", 1),
            "initial_exp": a.get("initial_exp", 0),
            "current_exp": a.get("current_exp", 0),
            "gained_exp": gained,
            "daily_limit_hit": is_limit_hit,
            "daily_limit": EXP_DAILY_LIMIT,
            "target_hit": is_target_hit,
            "matches_played": a.get("matches_played", 0),
            "status": status,
            "active_matches": a.get("active_matches", 0),
            "created_at": a.get("created_at"),
            "last_update": a.get("last_update"),
        })

    for acc in u.get("accounts", []):
        acc_type = acc.get("type")
        key = acc.get("uid") if acc_type == "guest" else acc.get("token", "")[:20]
        if not key:
            continue
        key_str = str(key)
        if key_str in deleted:
            continue

        already_live = False
        try:
            for live_uid, cred in list(ds.bot_state.account_credentials.items()):
                if str(live_uid) not in seen_real_ids:
                    continue
                if acc_type == "guest":
                    if str(cred.get("auth_uid", "")) == key_str:
                        already_live = True
                        break
                elif acc_type == "token":
                    if str(cred.get("auth_token", ""))[:20] == key_str:
                        already_live = True
                        break
        except Exception:
            pass
        if already_live:
            continue

        saved_real = str(acc.get("real_account_id") or "")
        if saved_real and saved_real in seen_real_ids:
            continue
        if key_str in seen_real_ids:
            continue

        is_paused = key_str in paused
        is_limit_hit = key_str in daily_hit
        is_target_hit = key_str in target_hit

        saved_exp = acc.get("last_exp", 0)
        saved_level = acc.get("last_level", 1)
        saved_nickname = acc.get("last_nickname", "Loading...")
        saved_region = acc.get("last_region", "IND")
        saved_initial = acc.get("initial_exp", saved_exp)
        saved_gained = acc.get("gained_exp", max(0, saved_exp - saved_initial))
        saved_played = acc.get("matches_played", 0)
        saved_created = acc.get("created_at")
        saved_updated = acc.get("last_update")

        display_uid = saved_real if saved_real else key_str

        if is_target_hit:
            status = "TARGET_DONE"
        elif is_limit_hit:
            status = "DAILY_LIMIT"
        elif is_paused:
            status = "PAUSED"
        else:
            status = "CONNECTING"

        out.append({
            "uid": display_uid,
            "nickname": saved_nickname,
            "region": saved_region,
            "level": saved_level,
            "initial_exp": saved_initial,
            "current_exp": saved_exp,
            "gained_exp": saved_gained,
            "daily_limit_hit": is_limit_hit,
            "daily_limit": EXP_DAILY_LIMIT,
            "target_hit": is_target_hit,
            "matches_played": saved_played,
            "status": status,
            "active_matches": 0,
            "created_at": saved_created,
            "last_update": saved_updated,
        })

    out.sort(key=lambda x: x.get("gained_exp", 0), reverse=True)
    return web.json_response({
        "username": un,
        "slots": u.get("slots", 0),
        "seconds_left": left,
        "expired": expired,
        "accounts": out,
        "auto_split": auto_split,
        "target_level": target_level,
        "one_time_run": int(u.get("one_time_run", 0) or 0),
        "active_batch": len(USER_ACTIVE_BATCH.get(un, set())),
    })


# ============================================================
# ACCOUNT HANDLERS
# ============================================================

async def h_acc_check(req):
    s = cur_user(req)
    if not s or s.get("is_admin"):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    un = s["username"]
    users = load_users()
    u = users.get(un)
    if not u:
        return web.json_response({"status": "error", "error": "User Missing"})
    if time.time() >= u.get("expires_at", 0):
        return web.json_response({"status": "error", "error": "Plan Expired"})
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    accs = u.setdefault("accounts", [])
    slots = u.get("slots", 0)
    un_deleted = USER_DELETED.get(un, set())
    active_accs = []
    for a in accs:
        key = str(a.get("uid")) if a.get("type") == "guest" else str(a.get("token", ""))[:20]
        if key and key not in un_deleted:
            active_accs.append(a)
    if len(active_accs) >= slots:
        return web.json_response({"status": "error", "error": "No Free Slots"})
    try:
        import main as m
    except Exception:
        return web.json_response({"status": "error", "error": "Main module unavailable"})
    acc_data = None
    if "uid" in d and "password" in d:
        uid = str(d["uid"]).strip()
        pw = str(d["password"]).strip()
        if not uid or not pw:
            return web.json_response({"status": "error", "error": "UID And Password Required"})
        for a in accs:
            if a.get("type") == "guest" and str(a.get("uid")) == uid:
                return web.json_response({"status": "error", "error": "UID Already Added"})
        cached = m.cache_get(uid)
        if cached and cached.get("level"):
            acc_data = cached
        else:
            try:
                acc_data = await m.process_account_uid_pass(uid, pw)
            except Exception:
                return web.json_response({"status": "error", "error": "Login Failed"})
    elif "token" in d:
        tk = str(d["token"]).strip()
        if not tk:
            return web.json_response({"status": "error", "error": "Token Required"})
        for a in accs:
            if a.get("type") == "token" and a.get("token") == tk:
                return web.json_response({"status": "error", "error": "Token Already Added"})
        cache_key = f"tok_{tk[:20]}"
        cached = m.cache_get(cache_key)
        if cached and cached.get("level"):
            acc_data = cached
        else:
            try:
                acc_data = await m.process_account_token(tk)
            except Exception:
                return web.json_response({"status": "error", "error": "Login Failed"})
    else:
        return web.json_response({"status": "error", "error": "Invalid Payload"})
    if not acc_data:
        return web.json_response({"status": "error", "error": "Login Failed"})
    return web.json_response({
        "status": "ok",
        "level": int(acc_data.get("level", 1) or 1),
        "region": str(acc_data.get("region", "") or "").upper(),
        "nickname": str(acc_data.get("nickname", "") or ""),
        "account_id": str(acc_data.get("account_id", "")),
    })


async def h_acc_add(req):
    s = cur_user(req)
    if not s or s.get("is_admin"):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    un = s["username"]
    users = load_users()
    u = users.get(un)
    if not u:
        return web.json_response({"status": "error", "error": "User Missing"})
    if time.time() >= u.get("expires_at", 0):
        return web.json_response({"status": "error", "error": "Plan Expired"})
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    accs = u.setdefault("accounts", [])
    slots = u.get("slots", 0)
    un_deleted = USER_DELETED.get(un, set())
    active_accs = []
    for a in accs:
        key = str(a.get("uid")) if a.get("type") == "guest" else str(a.get("token", ""))[:20]
        if key and key not in un_deleted:
            active_accs.append(a)
    if len(active_accs) >= slots:
        return web.json_response({"status": "error", "error": "No Free Slots"})
    if un not in USER_DELETED:
        USER_DELETED[un] = set()
    if un not in USER_PAUSED:
        USER_PAUSED[un] = set()
    if un not in USER_DAILY_LIMIT_HIT:
        USER_DAILY_LIMIT_HIT[un] = set()
    if un not in USER_TARGET_HIT:
        USER_TARGET_HIT[un] = set()

    today = _today_key()
    if "uid" in d and "password" in d:
        uid = str(d["uid"]).strip()
        pw = str(d["password"]).strip()
        if not uid or not pw:
            return web.json_response({"status": "error", "error": "UID And Password Required"})
        for a in accs:
            if a.get("type") == "guest" and str(a.get("uid")) == uid:
                return web.json_response({"status": "error", "error": "UID Already Added"})
        accs.append({
            "type": "guest", "uid": uid, "password": pw,
            "created_at": time.time(), "real_account_id": None,
            "last_reset_date": today, "daily_gained_exp": 0,
        })
    elif "token" in d:
        tk = str(d["token"]).strip()
        if not tk:
            return web.json_response({"status": "error", "error": "Token Required"})
        for a in accs:
            if a.get("type") == "token" and a.get("token") == tk:
                return web.json_response({"status": "error", "error": "Token Already Added"})
        accs.append({
            "type": "token", "token": tk,
            "created_at": time.time(), "real_account_id": None,
            "last_reset_date": today, "daily_gained_exp": 0,
        })
    else:
        return web.json_response({"status": "error", "error": "Invalid Payload"})
    u["accounts"] = accs
    users[un] = u
    save_users(users)
    asyncio.create_task(start_user_workers(un))
    return web.json_response({"status": "ok"})


async def _check_account_worker(sem, m, item, idx, existing_guest_uids, existing_tokens):
    async with sem:
        try:
            if not isinstance(item, dict):
                return ("error", {"index": idx, "reason": "Invalid entry"})
            uid = str(item.get("uid", "")).strip()
            password = str(item.get("password", "")).strip()
            token = str(item.get("token", "")).strip()
            if uid and password:
                if uid in existing_guest_uids:
                    return ("already", {"index": idx, "uid": uid, "reason": "Already added"})
                try:
                    cached = m.cache_get(uid)
                    if cached and cached.get("level"):
                        acc_data = cached
                    else:
                        acc_data = await m.process_account_uid_pass(uid, password)
                except Exception as e:
                    return ("error", {"index": idx, "uid": uid, "reason": f"Login error: {type(e).__name__}"})
                if not acc_data:
                    return ("error", {"index": idx, "uid": uid, "reason": "Login failed"})
                lvl = int(acc_data.get("level", 1) or 1)
                if lvl < 3:
                    return ("skipped", {"index": idx, "uid": uid, "reason": f"Level {lvl} < 3"})
                return ("added", {
                    "index": idx, "uid": uid, "password": password, "type": "guest",
                    "level": lvl, "nickname": acc_data.get("nickname", ""),
                    "account_id": str(acc_data.get("account_id", "")),
                    "exp": acc_data.get("exp", 0), "region": acc_data.get("region", ""),
                })
            elif token:
                if token in existing_tokens:
                    return ("already", {"index": idx, "token": token[:20], "reason": "Already added"})
                cache_key = f"tok_{token[:20]}"
                try:
                    cached = m.cache_get(cache_key)
                    if cached and cached.get("level"):
                        acc_data = cached
                    else:
                        acc_data = await m.process_account_token(token)
                except Exception as e:
                    return ("error", {"index": idx, "token": token[:20], "reason": f"Login error: {type(e).__name__}"})
                if not acc_data:
                    return ("error", {"index": idx, "token": token[:20], "reason": "Login failed"})
                lvl = int(acc_data.get("level", 1) or 1)
                if lvl < 3:
                    return ("skipped", {"index": idx, "token": token[:20], "reason": f"Level {lvl} < 3"})
                return ("added", {
                    "index": idx, "token": token, "type": "token",
                    "level": lvl, "nickname": acc_data.get("nickname", ""),
                    "account_id": str(acc_data.get("account_id", "")),
                    "exp": acc_data.get("exp", 0), "region": acc_data.get("region", ""),
                })
            else:
                return ("error", {"index": idx, "reason": "Missing uid/password or token"})
        except Exception as e:
            return ("error", {"index": idx, "reason": f"Exception: {type(e).__name__}"})


async def h_acc_bulk_add(req):
    s = cur_user(req)
    if not s or s.get("is_admin"):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    un = s["username"]
    users = load_users()
    u = users.get(un)
    if not u:
        return web.json_response({"status": "error", "error": "User Missing"})
    if time.time() >= u.get("expires_at", 0):
        return web.json_response({"status": "error", "error": "Plan Expired"})

    try:
        reader = await req.multipart()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid form data"})

    file_content = None
    target_level_req = 0
    one_time_run_req = 0
    auto_split_req = False

    while True:
        try:
            part = await reader.next()
        except Exception:
            break
        if part is None:
            break
        if part.name == 'file':
            try:
                file_content = await part.read()
            except Exception as e:
                return web.json_response({"status": "error", "error": f"File read error: {e}"})
        elif part.name == 'target_level':
            try:
                target_level_req = int(await part.text())
            except Exception:
                target_level_req = 0
        elif part.name == 'one_time_run':
            try:
                one_time_run_req = int(await part.text())
            except Exception:
                one_time_run_req = 0
        elif part.name == 'auto_split':
            try:
                auto_split_req = (await part.text()).lower() == "true"
            except Exception:
                auto_split_req = False

    if not file_content:
        return web.json_response({"status": "error", "error": "No file uploaded"})

    try:
        data = json.loads(file_content.decode('utf-8'))
    except Exception as e:
        return web.json_response({"status": "error", "error": f"Invalid JSON: {e}"})

    if isinstance(data, dict):
        accounts_list = data.get("accounts", [])
    elif isinstance(data, list):
        accounts_list = data
    else:
        return web.json_response({"status": "error", "error": "JSON must be list or {accounts:[...]}"})

    if not accounts_list:
        return web.json_response({"status": "error", "error": "No accounts in file"})

    try:
        import main as m
    except Exception:
        return web.json_response({"status": "error", "error": "Main module unavailable"})

    accs = u.setdefault("accounts", [])
    slots = u.get("slots", 0)
    un_deleted = USER_DELETED.get(un, set())
    active_accs = []
    for a in accs:
        key = str(a.get("uid")) if a.get("type") == "guest" else str(a.get("token", ""))[:20]
        if key and key not in un_deleted:
            active_accs.append(a)

    if un not in USER_DELETED:
        USER_DELETED[un] = set()
    if un not in USER_PAUSED:
        USER_PAUSED[un] = set()
    if un not in USER_DAILY_LIMIT_HIT:
        USER_DAILY_LIMIT_HIT[un] = set()
    if un not in USER_TARGET_HIT:
        USER_TARGET_HIT[un] = set()
    if un not in USER_ACTIVE_BATCH:
        USER_ACTIVE_BATCH[un] = set()

    existing_guest_uids = set()
    existing_tokens = set()
    for a in accs:
        if a.get("type") == "guest":
            existing_guest_uids.add(str(a.get("uid")))
        elif a.get("type") == "token":
            existing_tokens.add(a.get("token"))

    today = _today_key()
    slots_available = max(0, slots - len(active_accs))

    to_check = accounts_list[:slots_available] if len(accounts_list) > slots_available else accounts_list
    not_checked = accounts_list[slots_available:] if len(accounts_list) > slots_available else []

    # PARALLEL CHECK — threads
    sem = asyncio.Semaphore(BULK_CHECK_CONCURRENCY)
    tasks = []
    for idx, item in enumerate(to_check):
        tasks.append(_check_account_worker(sem, m, item, idx, existing_guest_uids, existing_tokens))
    results = await asyncio.gather(*tasks, return_exceptions=True)

    added = []
    skipped = []
    errors = []
    already_added = []

    for r in results:
        if isinstance(r, Exception):
            errors.append({"reason": f"Task error: {type(r).__name__}"})
            continue
        status, data = r
        if status == "added":
            added.append(data)
        elif status == "skipped":
            skipped.append(data)
        elif status == "already":
            already_added.append(data)
        elif status == "error":
            errors.append(data)

    for item in not_checked:
        skipped.append({"reason": f"No free slots ({slots} max)", "item": str(item)[:50]})

    for d in added:
        new_acc = {
            "created_at": time.time(),
            "real_account_id": d["account_id"],
            "initial_exp": d["exp"],
            "last_exp": d["exp"],
            "last_level": d["level"],
            "last_nickname": d["nickname"],
            "last_region": d["region"],
            "last_reset_date": today,
            "daily_gained_exp": 0,
        }
        if d["type"] == "guest":
            new_acc["type"] = "guest"
            new_acc["uid"] = d["uid"]
            new_acc["password"] = d["password"]
        else:
            new_acc["type"] = "token"
            new_acc["token"] = d["token"]
        accs.append(new_acc)

    u["accounts"] = accs

    if auto_split_req and target_level_req > 0 and one_time_run_req > 0:
        u["auto_split"] = True
        u["target_level"] = target_level_req
        u["one_time_run"] = one_time_run_req
    else:
        u["auto_split"] = False
        u["target_level"] = 0
        u["one_time_run"] = 0

    users[un] = u
    save_users(users)

    # Auto-split: pehla batch fill karo
    if u.get("auto_split"):
        active_batch = USER_ACTIVE_BATCH[un]
        active_batch.clear()
        count = 0
        for acc in accs:
            key = acc.get("uid") if acc.get("type") == "guest" else acc.get("token", "")[:20]
            if not key:
                continue
            if key in USER_TARGET_HIT[un] or key in USER_PAUSED[un]:
                continue
            active_batch.add(key)
            count += 1
            if count >= one_time_run_req:
                break
        print(f"[auto-split] Initial batch {un}: {count} accounts", flush=True)

    asyncio.create_task(start_user_workers(un))
    print(f"[api] Bulk add user={un} added={len(added)} skipped={len(skipped)} errors={len(errors)} already={len(already_added)} auto_split={u.get('auto_split')}", flush=True)

    return web.json_response({
        "status": "ok",
        "added": added, "skipped": skipped, "errors": errors, "already_added": already_added,
        "total_added": len(added), "total_skipped": len(skipped),
        "total_errors": len(errors), "total_already": len(already_added),
        "auto_split": u.get("auto_split", False),
        "target_level": u.get("target_level", 0),
        "one_time_run": u.get("one_time_run", 0),
    })


async def h_acc_del(req):
    s = cur_user(req)
    if not s or s.get("is_admin"):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    un = s["username"]
    users = load_users()
    u = users.get(un)
    if not u:
        return web.json_response({"status": "error", "error": "User Missing"})
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    uid = str(d.get("uid", "")).strip()
    if not uid:
        return web.json_response({"status": "error", "error": "Missing UID"})

    if un not in USER_DELETED:
        USER_DELETED[un] = set()
    if un not in USER_PAUSED:
        USER_PAUSED[un] = set()
    if un not in USER_DAILY_LIMIT_HIT:
        USER_DAILY_LIMIT_HIT[un] = set()
    if un not in USER_TARGET_HIT:
        USER_TARGET_HIT[un] = set()
    if un not in USER_ACTIVE_BATCH:
        USER_ACTIVE_BATCH[un] = set()

    real_uid = None
    real_token_prefix = None
    try:
        cred = ds.bot_state.account_credentials.get(uid)
        if cred:
            if cred.get("auth_uid"):
                real_uid = str(cred.get("auth_uid"))
            if cred.get("auth_token"):
                real_token_prefix = str(cred.get("auth_token"))[:20]
    except Exception:
        pass

    USER_DELETED[un].add(uid)
    if real_uid:
        USER_DELETED[un].add(real_uid)
    if real_token_prefix:
        USER_DELETED[un].add(real_token_prefix)
    for st in (USER_PAUSED, USER_DAILY_LIMIT_HIT, USER_TARGET_HIT, USER_ACTIVE_BATCH):
        if un in st:
            st[un].discard(uid)
            if real_uid:
                st[un].discard(real_uid)
            if real_token_prefix:
                st[un].discard(real_token_prefix)

    keys_to_kill = [uid]
    if real_uid:
        keys_to_kill.append(real_uid)
    if real_token_prefix:
        keys_to_kill.append(real_token_prefix)

    workers = USER_WORKERS.get(un, {})
    for k in keys_to_kill:
        t = workers.pop(k, None)
        if t and not t.done():
            t.cancel()
            try:
                await asyncio.wait_for(t, timeout=5)
            except Exception:
                pass

    for key in list(bot_state.account_workers.keys()):
        if str(key).startswith(un + "::"):
            suffix = str(key).split("::", 1)[1]
            if suffix in keys_to_kill:
                t = bot_state.account_workers.pop(key, None)
                if t and not t.done():
                    t.cancel()
                    try:
                        await asyncio.wait_for(t, timeout=3)
                    except Exception:
                        pass

    for k in keys_to_kill:
        try:
            ds.cache_invalidate(k)
        except Exception:
            pass

    removed = False
    accs_list = list(u.get("accounts", []))
    for acc in list(accs_list):
        acc_type = acc.get("type")
        acc_uid = str(acc.get("uid", ""))
        acc_token_prefix = str(acc.get("token", ""))[:20]
        acc_real = str(acc.get("real_account_id", ""))
        match = False
        if acc_type == "guest":
            if acc_uid == uid or (real_uid and acc_uid == real_uid) or (acc_real and acc_real == uid):
                match = True
        elif acc_type == "token":
            if acc_token_prefix == uid[:20] or (real_token_prefix and acc_token_prefix == real_token_prefix) or (acc_real and acc_real == uid):
                match = True
        if match:
            accs_list.remove(acc)
            removed = True
            break

    u["accounts"] = accs_list
    users[un] = u
    save_users(users)

    for k in keys_to_kill:
        if k in bot_state.accounts:
            bot_state.accounts.pop(k, None)
    await asyncio.sleep(0.5)
    for k in keys_to_kill:
        if k in bot_state.accounts:
            bot_state.accounts.pop(k, None)

    return web.json_response({"status": "ok", "removed": removed})


async def h_acc_pause(req):
    s = cur_user(req)
    if not s or s.get("is_admin"):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    un = s["username"]
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    uid = str(d.get("uid", "")).strip()
    if not uid:
        return web.json_response({"status": "error", "error": "Missing UID"})

    real_uid = None
    real_token_prefix = None
    try:
        cred = ds.bot_state.account_credentials.get(uid)
        if cred:
            if cred.get("auth_uid"):
                real_uid = str(cred.get("auth_uid"))
            if cred.get("auth_token"):
                real_token_prefix = str(cred.get("auth_token"))[:20]
    except Exception:
        pass

    if un not in USER_PAUSED:
        USER_PAUSED[un] = set()
    USER_PAUSED[un].add(uid)
    if real_uid:
        USER_PAUSED[un].add(real_uid)
    if real_token_prefix:
        USER_PAUSED[un].add(real_token_prefix)

    keys_to_kill = [uid]
    if real_uid:
        keys_to_kill.append(real_uid)
    if real_token_prefix:
        keys_to_kill.append(real_token_prefix)

    workers = USER_WORKERS.get(un, {})
    for k in keys_to_kill:
        t = workers.pop(k, None)
        if t and not t.done():
            t.cancel()
            try:
                await asyncio.wait_for(t, timeout=5)
            except Exception:
                pass

    for k in keys_to_kill:
        if k in bot_state.accounts:
            bot_state.accounts[k]["status"] = "PAUSED"

    return web.json_response({"status": "ok"})


async def h_acc_resume(req):
    s = cur_user(req)
    if not s or s.get("is_admin"):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    un = s["username"]
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    uid = str(d.get("uid", "")).strip()
    if not uid:
        return web.json_response({"status": "error", "error": "Missing UID"})

    real_uid = None
    real_token_prefix = None
    try:
        cred = ds.bot_state.account_credentials.get(uid)
        if cred:
            if cred.get("auth_uid"):
                real_uid = str(cred.get("auth_uid"))
            if cred.get("auth_token"):
                real_token_prefix = str(cred.get("auth_token"))[:20]
    except Exception:
        pass

    keys_to_release = [uid]
    if real_uid:
        keys_to_release.append(real_uid)
    if real_token_prefix:
        keys_to_release.append(real_token_prefix)

    for st in (USER_PAUSED, USER_DELETED, USER_DAILY_LIMIT_HIT, USER_TARGET_HIT):
        if un in st:
            for k in keys_to_release:
                st[un].discard(k)

    users = load_users()
    u = users.get(un, {})
    if time.time() < u.get("expires_at", 0):
        asyncio.create_task(start_user_workers(un))

    return web.json_response({"status": "ok"})


# ============================================================
# AUTO SPLIT CONFIG ENDPOINT
# ============================================================

async def h_acc_auto_split(req):
    """Enable/disable auto-split mode."""
    s = cur_user(req)
    if not s or s.get("is_admin"):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    un = s["username"]
    users = load_users()
    u = users.get(un)
    if not u:
        return web.json_response({"status": "error", "error": "User Missing"})
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})

    enable = bool(d.get("enable", False))
    target_level = int(d.get("target_level", 0) or 0)
    one_time_run = int(d.get("one_time_run", 0) or 0)

    if enable:
        if target_level < 1 or target_level > 100:
            return web.json_response({"status": "error", "error": "Target Level Must Be 1-100"})
        if one_time_run < 1 or one_time_run > 50:
            return web.json_response({"status": "error", "error": "One Time Run Must Be 1-50"})
        u["auto_split"] = True
        u["target_level"] = target_level
        u["one_time_run"] = one_time_run

        if un not in USER_TARGET_HIT:
            USER_TARGET_HIT[un] = set()
        if un not in USER_ACTIVE_BATCH:
            USER_ACTIVE_BATCH[un] = set()
        USER_TARGET_HIT[un].clear()
        USER_ACTIVE_BATCH[un].clear()

        accs = u.get("accounts", [])
        count = 0
        for acc in accs:
            key = acc.get("uid") if acc.get("type") == "guest" else acc.get("token", "")[:20]
            if not key:
                continue
            active_batch = USER_ACTIVE_BATCH[un]
            active_batch.add(key)
            count += 1
            if count >= one_time_run:
                break
    else:
        u["auto_split"] = False
        u["target_level"] = 0
        u["one_time_run"] = 0
        if un in USER_TARGET_HIT:
            USER_TARGET_HIT[un].clear()
        if un in USER_ACTIVE_BATCH:
            USER_ACTIVE_BATCH[un].clear()

    users[un] = u
    save_users(users)

    # Restart workers
    await stop_user_workers(un)
    asyncio.create_task(start_user_workers(un))

    return web.json_response({"status": "ok", "auto_split": u["auto_split"]})


# ============================================================
# ADMIN HANDLERS
# ============================================================

async def h_adm_login_get(req):
    s = cur_user(req)
    if s and s.get("is_admin"):
        raise web.HTTPFound(ADMIN_PATH + "/panel")
    return web.Response(text=ADMIN_LOGIN_HTML, content_type="text/html")


async def h_adm_login_post(req):
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    u = (d.get("username") or "").strip()
    p = d.get("password") or ""
    if u == ADMIN_USERNAME and p == ADMIN_PASSWORD:
        token = create_session(u, True)
        r = web.json_response({"status": "ok", "redirect": ADMIN_PATH + "/panel"})
        _set_ck(r, token)
        return r
    return web.json_response({"status": "error", "error": "Access Denied"})


async def h_adm_logout(req):
    token = req.cookies.get(SESSION_COOKIE)
    if token:
        destroy_session(token)
    r = web.HTTPFound(ADMIN_PATH)
    _clr_ck(r)
    raise r


async def h_adm_panel(req):
    if not cur_admin(req):
        raise web.HTTPFound(ADMIN_PATH)
    return web.Response(text=ADMIN_PANEL_HTML, content_type="text/html")


async def h_adm_create(req):
    if not cur_admin(req):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    u = (d.get("username") or "").strip()
    p = (d.get("password") or "").strip()
    slots = int(d.get("slots", 3))
    hours = int(d.get("hours", 24))
    if not u or not p:
        return web.json_response({"status": "error", "error": "Username And Password Required"})
    if slots < 1 or slots > MAX_SLOTS_LIMIT:
        return web.json_response({"status": "error", "error": f"Slots Must Be 1-{MAX_SLOTS_LIMIT}"})
    if hours < 1 or hours > 8760:
        return web.json_response({"status": "error", "error": "Hours Must Be 1-8760"})
    users = load_users()
    if u in users:
        return web.json_response({"status": "error", "error": "Username Already Exists"})
    ph, salt = hash_pw(p)
    now = time.time()
    users[u] = {
        "password_hash": ph, "salt": salt, "slots": slots, "plan_hours": hours,
        "created_at": now, "expires_at": now + hours * 3600, "accounts": [],
        "_expired_flag": False, "auto_split": False, "target_level": 0, "one_time_run": 0,
    }
    save_users(users)
    return web.json_response({"status": "ok"})


async def h_adm_list(req):
    if not cur_admin(req):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    users = load_users()
    out = []
    for un, u in users.items():
        used = sum(1 for a in ds.bot_state.accounts.values() if a.get("_owner") == un)
        out.append({
            "username": un, "slots": u.get("slots", 0), "used_slots": used,
            "expires_at": u.get("expires_at", 0), "created_at": u.get("created_at", 0),
        })
    out.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return web.json_response({"status": "ok", "users": out})


async def h_adm_ext(req):
    if not cur_admin(req):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    un = d.get("username", "").strip()
    hours = int(d.get("hours", 24))
    users = load_users()
    u = users.get(un)
    if not u:
        return web.json_response({"status": "error", "error": "User Not Found"})
    now = time.time()
    base = max(now, u.get("expires_at", 0))
    u["expires_at"] = base + hours * 3600
    u["_expired_flag"] = False
    save_users(users)
    if un in USER_DELETED:
        USER_DELETED[un].clear()
    asyncio.create_task(start_user_workers(un))
    return web.json_response({"status": "ok"})


async def h_adm_slot(req):
    if not cur_admin(req):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    un = d.get("username", "").strip()
    count = int(d.get("count", 1))
    users = load_users()
    u = users.get(un)
    if not u:
        return web.json_response({"status": "error", "error": "User Not Found"})
    u["slots"] = min(MAX_SLOTS_LIMIT, u.get("slots", 0) + count)
    save_users(users)
    return web.json_response({"status": "ok", "slots": u["slots"]})


async def h_adm_del(req):
    if not cur_admin(req):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    un = d.get("username", "").strip()
    users = load_users()
    if un not in users:
        return web.json_response({"status": "error", "error": "User Not Found"})
    await stop_user_workers(un)
    users.pop(un, None)
    save_users(users)
    USER_PAUSED.pop(un, None)
    USER_DELETED.pop(un, None)
    USER_WORKERS.pop(un, None)
    USER_DAILY_LIMIT_HIT.pop(un, None)
    USER_TARGET_HIT.pop(un, None)
    USER_ACTIVE_BATCH.pop(un, None)
    return web.json_response({"status": "ok"})


async def h_adm_reset_pw(req):
    if not cur_admin(req):
        return web.json_response({"status": "error", "error": "unauthorized"}, status=401)
    try:
        d = await req.json()
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid JSON"})
    un = d.get("username", "").strip()
    new_pw = d.get("password", "").strip()
    if not un or not new_pw:
        return web.json_response({"status": "error", "error": "Username And Password Required"})
    users = load_users()
    u = users.get(un)
    if not u:
        return web.json_response({"status": "error", "error": "User Not Found"})
    ph, salt = hash_pw(new_pw)
    u["password_hash"] = ph
    u["salt"] = salt
    users[un] = u
    save_users(users)
    return web.json_response({"status": "ok"})


# ============================================================
# EXPIRY WATCHER + DAILY 4AM RESET
# ============================================================

async def expiry_watcher():
    last_reset_day = _today_key()
    while True:
        try:
            users = load_users()
            now = time.time()
            changed = False
            for un, u in users.items():
                exp = now >= u.get("expires_at", 0)
                was = u.get("_expired_flag", False)
                if exp and not was:
                    await stop_user_workers(un)
                    u["_expired_flag"] = True
                    changed = True
                elif not exp and was:
                    u["_expired_flag"] = False
                    changed = True
                    asyncio.create_task(start_user_workers(un))

            current_day = _today_key()
            if current_day != last_reset_day:
                last_reset_day = current_day
                print(f"[expiry] Daily 4AM reset for {current_day}", flush=True)
                for un in list(USER_DAILY_LIMIT_HIT.keys()):
                    try:
                        USER_DAILY_LIMIT_HIT[un].clear()
                        users2 = load_users()
                        u2 = users2.get(un, {})
                        for acc in u2.get("accounts", []):
                            acc["last_reset_date"] = current_day
                            acc["daily_gained_exp"] = 0
                            acc["initial_exp"] = None
                            acc["gained_exp"] = 0
                        save_users(users2)
                        if time.time() < u2.get("expires_at", 0):
                            asyncio.create_task(start_user_workers(un))
                    except Exception as e:
                        print(f"[expiry] Reset error for {un}: {e}", flush=True)

            if changed:
                save_users(users)
        except Exception as e:
            print(f"[expiry] watcher error: {e}", flush=True)
        await asyncio.sleep(5)


# ============================================================
# STARTUP
# ============================================================

async def start_web_dashboard(host="0.0.0.0", port=20335):
    app = web.Application()

    app.router.add_get("/", h_root)
    app.router.add_get("/login", h_login_get)
    app.router.add_post("/login", h_login_post)
    app.router.add_get("/signup", h_signup)
    app.router.add_get("/plans", h_plans)
    app.router.add_get("/logout", h_logout)
    app.router.add_get("/dashboard", h_dash)
    app.router.add_get("/expired", h_expired)

    app.router.add_get("/api/stats", h_stats)
    app.router.add_post("/api/account/check", h_acc_check)
    app.router.add_post("/api/account/add", h_acc_add)
    app.router.add_post("/api/account/bulk-add", h_acc_bulk_add)
    app.router.add_post("/api/account/delete", h_acc_del)
    app.router.add_post("/api/account/pause", h_acc_pause)
    app.router.add_post("/api/account/resume", h_acc_resume)
    app.router.add_post("/api/account/auto-split", h_acc_auto_split)

    app.router.add_get(ADMIN_PATH, h_adm_login_get)
    app.router.add_post(ADMIN_PATH, h_adm_login_post)
    app.router.add_get(ADMIN_PATH + "/logout", h_adm_logout)
    app.router.add_get(ADMIN_PATH + "/panel", h_adm_panel)

    app.router.add_post("/api/admin/create-user", h_adm_create)
    app.router.add_get("/api/admin/list-users", h_adm_list)
    app.router.add_post("/api/admin/extend-time", h_adm_ext)
    app.router.add_post("/api/admin/add-slot", h_adm_slot)
    app.router.add_post("/api/admin/delete-user", h_adm_del)
    app.router.add_post("/api/admin/reset-password", h_adm_reset_pw)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    print(f"Web Dashboard Running On http://{host}:{port}", flush=True)
    print(f"Admin Panel: http://{host}:{port}{ADMIN_PATH}", flush=True)

    asyncio.create_task(expiry_watcher())

    try:
        users = load_users()
        now = time.time()
        for un, u in users.items():
            if now < u.get("expires_at", 0):
                asyncio.create_task(start_user_workers(un))
    except Exception:
        pass


__all__ = ["bot_state", "start_web_dashboard"]