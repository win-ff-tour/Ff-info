import os
import time
import binascii
import logging
from datetime import datetime

try:
    from zoneinfo import ZoneInfo
    TIMEZONE_AVAILABLE = True
except ImportError:
    TIMEZONE_AVAILABLE = False

import requests
from flask import Flask, jsonify, request
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from proto.data_pb2 import AccountPersonalShowInfo
from proto import uid_generator_pb2



app = Flask(__name__)
app.json.sort_keys = False



logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)



RELEASE_VERSION = "OB55"

USER_AGENT = (
    "Dalvik/2.1.0 (Linux; U; Android 9; "
    "ASUS_Z01QD Build/PI)"
)

DEFAULT_KEY = "Yg&tc%DEuh6%Zc^8"
DEFAULT_IV = "6oyZDr22E3ychjM%"





def create_http_session():
    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.2,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(
        max_retries=retry,
        pool_connections=50,
        pool_maxsize=50
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


http_session = create_http_session()



def get_formatted_time():
    if TIMEZONE_AVAILABLE:
        try:
            return datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%I:%M %p, %A, %B %d, %Y")
        except Exception:
            pass
    return datetime.now().strftime("%I:%M %p, %A, %B %d, %Y")


def get_iso_time():
    if TIMEZONE_AVAILABLE:
        try:
            return datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()
        except Exception:
            pass
    return datetime.now().isoformat()



def proto_to_dict(message):
    result = {}
    for field in getattr(message.DESCRIPTOR, "fields", []):
        value = getattr(message, field.name)
        val_type = type(value).__name__

        if "MapContainer" in val_type:
            map_result = {}
            for key, item in value.items():
                if hasattr(item, "DESCRIPTOR"):
                    map_result[key] = proto_to_dict(item)
                elif isinstance(item, bytes):
                    map_result[key] = binascii.hexlify(item).decode("utf-8")
                else:
                    map_result[key] = item
            result[field.name] = map_result

        elif "Repeated" in val_type:
            list_result = []
            for item in value:
                if hasattr(item, "DESCRIPTOR"):
                    list_result.append(proto_to_dict(item))
                elif isinstance(item, bytes):
                    list_result.append(binascii.hexlify(item).decode("utf-8"))
                else:
                    list_result.append(item)
            result[field.name] = list_result

        elif hasattr(value, "DESCRIPTOR"):
            result[field.name] = proto_to_dict(value)

        elif getattr(field, "type", None) == 14:
            try:
                result[field.name] = field.enum_type.values_by_number[value].name
            except Exception:
                result[field.name] = value

        elif isinstance(value, bytes):
            result[field.name] = binascii.hexlify(value).decode("utf-8") if value else ""

        else:
            result[field.name] = value

    return result



def extract_token(data):
    if not isinstance(data, dict):
        return None
    token = data.get("jwt_token") or data.get("token") or data.get("access_token")
    if token:
        return token
    nested = data.get("data")
    if isinstance(nested, dict):
        token = nested.get("jwt_token") or nested.get("token") or nested.get("access_token")
        if token:
            return token
    return None


def normalize_token(token):
    if not token:
        return None
    token = str(token).strip()
    if token.startswith("Bearer "):
        return token[7:].strip()
    return token


def ensure_jwt_token_sync(region, force_refresh=False):
    region = (region or "BD").upper()
    if region not in {"BD", "IND"}:
        raise ValueError("Only BD and IND regions are supported")
    env_name = "JWT_TOKEN_{}".format(region)
    token = normalize_token(os.getenv(env_name))
    if not token:
        raise RuntimeError("Not configured")
    return token


def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BD": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
    }
    if region not in endpoints:
        raise ValueError("Only BD and IND regions are supported")
    return endpoints[region]


def encrypt_aes(hex_data, key, iv):
    key_bytes = key.encode()[:16]
    iv_bytes = iv.encode()[:16]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded_data)).decode()


def make_headers(token):
    return {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": "1789534056",
        "Authorization": f"Bearer {normalize_token(token)}",
        "X-Ga": "v1 1",
        "Releaseversion": RELEASE_VERSION,
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2018.4.12f1",
        "PlAy_VeR": "1.132.1",
        "Ob_VeR": RELEASE_VERSION
    }



def apis(encrypted_hex, region):
    region = (region or "BD").upper()
    endpoint = get_api_endpoint(region)

    for attempt in range(2):
        token = ensure_jwt_token_sync(region, force_refresh=(attempt > 0))
        headers = make_headers(token)
        try:
            response = http_session.post(
                endpoint,
                headers=headers,
                data=bytes.fromhex(encrypted_hex),
                timeout=6
            )
            if response.status_code in [401, 429]:
                logger.warning("[%s] Received status %s, rotating account...", region, response.status_code)
                continue
            response.raise_for_status()
            return response.content.hex()
        except requests.exceptions.RequestException:
            if attempt == 1:
                raise
    raise Exception("API request failed after rotation attempts")


def format_response(result):
    basic = result.get("basic_info", {})
    profile = result.get("profile_info", {})
    clan = result.get("clan_basic_info", {})
    captain = result.get("captain_basic_info", {})
    pet = result.get("pet_info", {})
    social = result.get("social_info", {})
    diamond = result.get("diamond_cost_res", {})
    credit = result.get("credit_score_info", {})

    return {
        "basicInfo": {
            "accountId": basic.get("account_id", 0),
            "accountType": basic.get("account_type", 0),
            "nickname": basic.get("nickname", ""),
            "region": basic.get("region", ""),
            "level": basic.get("level", 0),
            "exp": basic.get("exp", 0),
            "bannerId": basic.get("banner_id", 0),
            "headPic": basic.get("head_pic", 0),
            "rank": basic.get("rank", 0),
            "rankingPoints": basic.get("ranking_points", 0),
            "role": 0,
            "hasElitePass": basic.get("has_elite_pass", False),
            "badgeCnt": basic.get("badge_cnt", 0),
            "badgeId": basic.get("badge_id", 0),
            "seasonId": basic.get("season_id", 0),
            "liked": basic.get("liked", 0),
            "lastLoginAt": str(basic.get("last_login_at", 0)),
            "csRank": basic.get("cs_rank", 0),
            "csRankingPoints": basic.get("cs_ranking_points", 0),
            "weaponSkinShows": basic.get("weapon_skin_shows", []),
            "maxRank": basic.get("max_rank", 0),
            "csMaxRank": basic.get("cs_max_rank", 0),
            "accountPrefers": basic.get("account_prefers", {}),
            "createAt": str(basic.get("create_at", 0)),
            "title": basic.get("title", 0),
            "externalIconInfo": basic.get("external_icon_info", {}),
            "releaseVersion": basic.get("release_version", ""),
            "showBrRank": basic.get("show_br_rank", False),
            "showCsRank": basic.get("show_cs_rank", False),
            "socialHighLightsWithBasicInfo": {}
        },
        "profileInfo": {
            "avatarId": profile.get("avatar_id", 0),
            "skinColor": 0,
            "clothes": profile.get("cosmetic_items", []),
            "equipedSkills": profile.get("equipped_skills", []),
            "isSelected": True,
            "isSelectedAwaken": False,
            "unlockTime": profile.get("skin_unlock_time", 0)
        },
        "clanBasicInfo": {
            "clanId": str(clan.get("clan_id", 0)),
            "clanName": clan.get("clan_name", ""),
            "captainId": str(clan.get("captain_id", 0)),
            "clanLevel": clan.get("clan_level", 0),
            "capacity": clan.get("max_members", 0),
            "memberNum": clan.get("current_members", 0)
        },
        "captainBasicInfo": {
            "accountId": str(captain.get("account_id", 0)),
            "accountType": captain.get("account_type", 0),
            "nickname": captain.get("nickname", ""),
            "region": captain.get("region", ""),
            "level": captain.get("level", 0),
            "exp": captain.get("exp", 0),
            "bannerId": captain.get("banner_id", 0),
            "headPic": captain.get("head_pic", 0),
            "rank": captain.get("rank", 0),
            "rankingPoints": captain.get("ranking_points", 0),
            "role": 0,
            "hasElitePass": captain.get("has_elite_pass", False),
            "badgeCnt": captain.get("badge_cnt", 0),
            "badgeId": captain.get("badge_id", 0),
            "seasonId": captain.get("season_id", 0),
            "liked": captain.get("liked", 0),
            "lastLoginAt": str(captain.get("last_login_at", 0)),
            "csRank": captain.get("cs_rank", 0),
            "csRankingPoints": captain.get("cs_ranking_points", 0),
            "weaponSkinShows": captain.get("weapon_skin_shows", []),
            "maxRank": captain.get("max_rank", 0),
            "csMaxRank": captain.get("cs_max_rank", 0),
            "accountPrefers": captain.get("account_prefers", {}),
            "createAt": str(captain.get("create_at", 0)),
            "title": captain.get("title", 0),
            "externalIconInfo": captain.get("external_icon_info", {}),
            "releaseVersion": captain.get("release_version", ""),
            "showBrRank": captain.get("show_br_rank", False),
            "showCsRank": captain.get("show_cs_rank", False),
            "socialHighLightsWithBasicInfo": {}
        },
        "petInfo": {
            "id": pet.get("pet_id", 0),
            "level": pet.get("level", 0),
            "exp": pet.get("exp", 0),
            "isSelected": pet.get("is_selected", False),
            "skinId": pet.get("skin_id", 0),
            "selectedSkillId": pet.get("selected_skill_id", 0),
            "isMarkedStar": False
        },
        "socialInfo": {
            "accountId": str(social.get("account_id", 0)),
            "gender": social.get("gender", ""),
            "language": social.get("language", ""),
            "modePrefer": "",
            "signature": social.get("social_highlight", ""),
            "rankShow": ""
        },
        "diamondCostRes": {
            "diamondCost": diamond.get("diamond_cost", 0)
        },
        "creditScoreInfo": {
            "creditScore": credit.get("score", 0),
            "rewardState": "",
            "periodicSummaryEndTime": str(credit.get("end", 0))
        },
        "auth": "TG: @FFxAPI",
        "create": "eVe"
    }



@app.route("/", methods=["GET"])
def home():
    return """<!doctype html><html><head><meta charset="utf-8"><title>OB55 Player Full Info API</title></head><body><h2>OB55 Player Full Info API</h2><h3>Endpoints</h3><ul><li><code>GET /health</code></li><li><code>GET /ffinfo?uid={}&amp;region={}</code></li></ul><p>Supported regions: <code>BD</code>, <code>IND</code></p></body></html>"""


@app.route("/ffinfo", methods=["GET"])
@app.route("/info", methods=["GET"])
def get_player_info():
    start_time = time.time()
    try:
        uid = request.args.get("uid")
        region = request.args.get("region", "BD").upper()
        if region not in {"BD", "IND"}:
            return jsonify({"error": "Only BD and IND regions are supported"}), 400
        custom_key = request.args.get("key", DEFAULT_KEY)
        custom_iv = request.args.get("iv", DEFAULT_IV)

        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        try:
            uid_int = int(uid)
        except ValueError:
            return jsonify({"error": "Invalid UID format"}), 400

        message = uid_generator_pb2.uid_generator()
        message.saturn_ = uid_int
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()

        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        api_response = apis(encrypted_hex, region)

        if not api_response:
            return jsonify({"error": "Empty response from API"}), 502

        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response))
        result = format_response(proto_to_dict(message))

        return jsonify(result), 200

    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400

    except Exception as e:
        logger.exception("[INFO ERROR] %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/favicon.ico")
def favicon():
    return "", 404


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Free Fire Player Info API",
        "regions": ["BD", "IND"],
        "time": get_iso_time()
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT")),
        threaded=True
    )
