#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
外部 OpenAPI 鉴权签名工具（AK/SK 签名模式）
========================================================================================

一、依据
----------------------------------------------------------------------------------------
FinvQuant 仓库 `Docs/API/OpenAPI/Auth.md` §3「模式二：AK/SK 签名」（需求 11168 /
11177 / 11179）：

    POST /OpenAPI/V1/Meta/Finv/Quote/Cdeu/Min/Upsert?onConflict=update
    Authorization: META1-HMAC-SHA256 Credential=AK_LIVE_XXXX, Signature=<base64>
    X-META-TS: 1737000000
    X-META-Nonce: 8e2f1c9a4b7d4c0e
    Content-Type: application/json

> 旧写法（`Authorization: FinvAK <AK>:<签名>` + `X-Finv-Timestamp` /
> `X-Finv-Nonce`）已废止，不要再使用。

二、待签串（canonical string，6 段，用 `\\n` 连接）
----------------------------------------------------------------------------------------
    METHOD \\n PATH \\n SORTED_QUERY \\n BODY_SHA256 \\n TIMESTAMP \\n NONCE

| 段 | 取值 |
| --- | --- |
| `METHOD` | 大写 HTTP 方法 |
| `PATH` | 请求路径，**不含**域名、端口与查询串 |
| `SORTED_QUERY` | 参数名升序、同名参数的值也升序，键与值都做 RFC 3986 编码（空格 → `%20`），再以 `&` 连接；无查询串时为空行 |
| `BODY_SHA256` | 请求体 SHA-256 十六进制**大写**；GET / 空体用 `sha256("")` 的大写形式 |
| `TIMESTAMP` | 与 `X-META-TS` 完全一致的 Unix 秒字符串 |
| `NONCE` | 与 `X-META-Nonce` 完全一致的随机串（建议 8~64 位，每次请求不同） |

三、签名
----------------------------------------------------------------------------------------
    signature = Base64( HMAC-SHA256( SK, canonical ) )

`Authorization: META1-<算法名> Credential=<AK>, Signature=<base64 签名>`，
`META1-` 后的算法名须与凭证登记的 `sign_algorithm` 一致（本项目为 `HMAC-SHA256`）。

四、用法（调用方脚本与本模块位于同一目录，可直接 import）
----------------------------------------------------------------------------------------
    import OpenApiAuthSign

    # 1) 取 AK/SK：默认读 API_QUOTE_UPSERT_AK / API_QUOTE_UPSERT_SK；
    #    返回 ("", "") 表示未配置（调用方可按无鉴权处理），只配一个则抛
    #    AuthConfigError，避免半残配置静默降级
    access_key, secret_key = OpenApiAuthSign.load_credentials()

    # 2) 每次请求现算（时间戳与 nonce 必须新鲜，重试时也要重算）
    headers = OpenApiAuthSign.build_auth_headers(
        "POST", "/OpenAPI/V1/Meta/Finv/Quote/Cdeu/Min/Upsert",
        "onConflict=update", body_bytes, access_key, secret_key)

    # 3) 联调自检：只看待签串与签名，不发起请求
    text = OpenApiAuthSign.canonical_string(
        "POST", path, query, body_bytes, "1737000000", "8e2f1c9a4b7d4c0e")

约定：
    - 只依赖标准库；不缓存、不落盘任何凭证；
    - `secret_key` **绝不打印 / 不写日志**；`access_key` 需要展示时用
      `mask_access_key()` 脱敏；
    - 时间戳与 nonce 由本模块生成，调用方无需自行维护（需要固定值时显式传入，
      便于单测与联调复现）。
"""

import base64
import hashlib
import hmac
import os
import secrets
import time as time_module
import urllib.parse

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

# 鉴权方案前缀与签名算法（须与凭证登记的 sign_algorithm 一致，全大写比对）
AUTH_SCHEME_PREFIX = "META1-"
SIGN_ALGORITHM = "HMAC-SHA256"
AUTH_SCHEME = AUTH_SCHEME_PREFIX + SIGN_ALGORITHM   # Authorization 头前缀

# 请求头名
HEADER_AUTHORIZATION = "Authorization"
HEADER_TIMESTAMP = "X-META-TS"
HEADER_NONCE = "X-META-Nonce"

# 空体摘要（GET / 无请求体）：sha256("") 的十六进制大写，可直接复用避免重算
EMPTY_BODY_SHA256 = hashlib.sha256(b"").hexdigest().upper()

# nonce 随机字节数：16 字节 → 32 位十六进制，落在服务端建议的 8~64 位区间内
NONCE_BYTES = 16

# 默认环境变量名（GitHub Actions 侧由 Secrets 注入同名变量）
DEFAULT_ACCESS_KEY_ENV = "API_QUOTE_UPSERT_AK"
DEFAULT_SECRET_KEY_ENV = "API_QUOTE_UPSERT_SK"

# RFC 3986 未保留字符：除字母数字外，仅 -._~ 无需百分号编码
_RFC3986_SAFE = "-._~"


class AuthConfigError(ValueError):
    """AK/SK 配置不完整或不合法（调用方应视为致命配置错误）"""


# ---------------------------------------------------------------------------
# 待签串与签名
# ---------------------------------------------------------------------------

def _to_bytes(value):
    """把 body 统一转成 bytes：str 按 UTF-8 编码，None 视为空体"""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    return str(value).encode("utf-8")


def rfc3986_encode(value):
    """RFC 3986 百分号编码：仅字母数字与 `-._~` 原样保留（空格 → `%20`）

    > 注意不能用 `quote_plus`：它把空格编码为 `+`，与服务端待签串不一致。
    """
    return urllib.parse.quote(str(value), safe=_RFC3986_SAFE)


def canonical_query(query):
    """把查询串规范化为 SORTED_QUERY

    :param query: 原始查询串（如 "b=2&a=1"，不含前导 `?`），None / 空串指无查询串
    :return: 参数名升序、同名参数值升序，键值均 RFC 3986 编码后以 `&` 连接；
             无查询串时返回空串（待签串中即为空行）

    解析用 `parse_qsl`（保留空值、`+` 还原为空格后再编码回 `%20`），
    排序作用于**编码后**的键值，保证不同实现得到同一结果。
    """
    text = (query or "").lstrip("?")
    if not text:
        return ""
    pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
    encoded = sorted((rfc3986_encode(key), rfc3986_encode(value))
                     for key, value in pairs)
    return "&".join("%s=%s" % (key, value) for key, value in encoded)


def body_sha256(body):
    """请求体摘要：SHA-256 十六进制大写；空体即 EMPTY_BODY_SHA256"""
    return hashlib.sha256(_to_bytes(body)).hexdigest().upper()


def canonical_string(method, path, query, body, timestamp, nonce):
    """拼 6 段待签串（换行连接，空段保留空行）

    :param method: HTTP 方法（大小写不敏感，内部转大写）
    :param path: 请求路径（不含域名 / 端口 / 查询串）
    :param query: 查询串（不含前导 `?`），可为空
    :param body: 请求体（bytes / str / None）
    :param timestamp: Unix 秒字符串，须与 X-META-TS 完全一致
    :param nonce: 随机串，须与 X-META-Nonce 完全一致
    :return: 待签串文本
    """
    return "\n".join((
        str(method or "").upper(),
        str(path or ""),
        canonical_query(query),
        body_sha256(body),
        str(timestamp or ""),
        str(nonce or ""),
    ))


def sign(secret_key, canonical):
    """Base64(HMAC-SHA256(SK, canonical))

    :param secret_key: SK（明文，调用方注入，勿落盘）
    :param canonical: 待签串文本
    :return: Base64 签名字符串
    """
    if not secret_key:
        raise AuthConfigError("SK 为空，无法计算签名")
    digest = hmac.new(str(secret_key).encode("utf-8"),
                      str(canonical).encode("utf-8"),
                      hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


# ---------------------------------------------------------------------------
# 请求头与凭证
# ---------------------------------------------------------------------------

def build_auth_headers(method, path, query, body, access_key, secret_key,
                       timestamp=None, nonce=None):
    """构造鉴权请求头（每次请求现算，时间窗与 nonce 去重要求每次不同）

    :return: dict，含 Authorization / X-META-TS / X-META-Nonce
    :raises AuthConfigError: AK 或 SK 缺失

    > 重试 / 413 二分后重发时必须重新调用本函数：时间戳超过服务端时间窗
    > （默认 300 秒）或 nonce 重复都会被拒（19006 / 19007）。
    """
    access_key = (access_key or "").strip()
    secret_key = (secret_key or "").strip()
    if not access_key or not secret_key:
        raise AuthConfigError("AK/SK 不完整，无法签名（需同时提供）")

    ts = str(timestamp) if timestamp is not None else str(int(time_module.time()))
    nonce_value = str(nonce) if nonce is not None else secrets.token_hex(NONCE_BYTES)
    canonical = canonical_string(method, path, query, body, ts, nonce_value)
    return {
        HEADER_AUTHORIZATION: "%s Credential=%s, Signature=%s" % (
            AUTH_SCHEME, access_key, sign(secret_key, canonical)),
        HEADER_TIMESTAMP: ts,
        HEADER_NONCE: nonce_value,
    }


def load_credentials(access_env=DEFAULT_ACCESS_KEY_ENV,
                     secret_env=DEFAULT_SECRET_KEY_ENV):
    """从环境变量读取 AK/SK

    :return: (access_key, secret_key)；两者都为空时返回 ("", "")，表示未配置鉴权
    :raises AuthConfigError: 只配置了其中一个（半残配置直接失败，避免静默降级）

    默认变量名 API_QUOTE_UPSERT_AK / API_QUOTE_UPSERT_SK 与 GitHub Secrets 同名，
    由 workflow 的 env 映射注入；其它接口复用时传自定义变量名即可。
    """
    access_key = os.environ.get(access_env, "").strip()
    secret_key = os.environ.get(secret_env, "").strip()
    if access_key and secret_key:
        return access_key, secret_key
    if access_key or secret_key:
        missing = secret_env if access_key else access_env
        raise AuthConfigError(
            "AK/SK 配置不完整：缺少环境变量 %s（两者必须同时提供，"
            "否则服务端会按 19002 拒绝）" % missing)
    return "", ""


def mask_access_key(access_key):
    """AK 脱敏展示（AK 本身是公开标识，但仍只显示首尾便于人工核对）"""
    text = (access_key or "").strip()
    if not text:
        return "(未配置)"
    if len(text) <= 12:
        return text[:4] + "***"
    return "%s***%s" % (text[:8], text[-4:])


# ---------------------------------------------------------------------------
# 自检（不联网）：python3 OpenApiAuthSign.py
# ---------------------------------------------------------------------------

def _demo():
    """打印一组固定输入的待签串与签名，便于与 Go 端 / 服务端联调比对"""
    method, path, query = "POST", "/OpenAPI/V1/Meta/Finv/Quote/Cdeu/Min/Upsert", \
        "onConflict=update"
    body = b'{"items": []}'
    ts, nonce = "1737000000", "8e2f1c9a4b7d4c0e"
    text = canonical_string(method, path, query, body, ts, nonce)
    print("canonical string:")
    for line in text.split("\n"):
        print("    %s" % line)
    print("signature = %s" % sign("SK_DEMO_FOR_SELF_TEST_ONLY", text))


if __name__ == "__main__":
    _demo()
