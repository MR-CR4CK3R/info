
import asyncio
import time
import httpx
import json
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
MAIN_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
RELEASEVERSION = "OB50"  # Updated to OB50
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3969792022&password=9891BF5C966DB63C38990E9A95B1916A47493EB982E4DDA18C0CE1DF26ED6330"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3957942405&password=C762C429481752AAE664A92D6E99DF731D4AE16056129933F8BF823749AA3D41"
    else:
        return "uid=4210779683&password=MR_CRACKER-CCG1YSJSL-TOC-BD"

# === Fixed Token Generation ===
async def get_access_token(account: str):
    # Updated URL - using the working endpoint
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    
    # Updated headers to match working config
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.post(url, data=payload, headers=headers, timeout=10)
            if resp.status_code != 200:
                return "0", "0"
            data = resp.json()
            return data.get("access_token", "0"), data.get("open_id", "0")
        except Exception:
            return "0", "0"

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    
    if token_val == "0" or open_id == "0":
        print(f"Failed to get access token for region {region}")
        return
    
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    
    # Updated login endpoint
    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.post(url, data=payload, headers=headers, timeout=15)
            if resp.status_code == 200:
                msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
                cached_tokens[region] = {
                    'token': f"Bearer {msg.get('token','0')}",
                    'region': msg.get('lockRegion','0'),
                    'server_url': msg.get('serverUrl','0'),
                    'expires_at': time.time() + 25200
                }
                print(f"JWT created successfully for region {region}")
            else:
                print(f"Failed to create JWT for region {region}: HTTP {resp.status_code}")
        except Exception as e:
            print(f"Error creating JWT for region {region}: {e}")

async def initialize_tokens():
    print("Initializing tokens for all regions...")
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks, return_exceptions=True)
    print(f"Token initialization complete. Cached tokens for regions: {list(cached_tokens.keys())}")

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)  # 7 hours
        print("Refreshing tokens...")
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    
    print(f"Token expired or missing for region {region}, creating new one...")
    await create_jwt(region)
    info = cached_tokens.get(region)
    if info:
        return info['token'], info['region'], info['server_url']
    else:
        raise Exception(f"Failed to get token for region {region}")

async def GetAccountInformation(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers, timeout=15)
        if resp.status_code == 200:
            return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))
        else:
            raise Exception(f"API request failed: HTTP {resp.status_code}")

def format_response(data):
    return {
        "AccountInfo": {
            "AccountAvatarId": data.get("basicInfo", {}).get("headPic"),
            "AccountBPBadges": data.get("basicInfo", {}).get("badgeCnt"),
            "AccountBPID": data.get("basicInfo", {}).get("badgeId"),
            "AccountBannerId": data.get("basicInfo", {}).get("bannerId"),
            "AccountCreateTime": data.get("basicInfo", {}).get("createAt"),
            "AccountEXP": data.get("basicInfo", {}).get("exp"),
            "AccountLastLogin": data.get("basicInfo", {}).get("lastLoginAt"),
            "AccountLevel": data.get("basicInfo", {}).get("level"),
            "AccountLikes": data.get("basicInfo", {}).get("liked"),
            "AccountName": data.get("basicInfo", {}).get("nickname"),
            "AccountRegion": data.get("basicInfo", {}).get("region"),
            "AccountSeasonId": data.get("basicInfo", {}).get("seasonId"),
            "AccountType": data.get("basicInfo", {}).get("accountType"),
            "BrMaxRank": data.get("basicInfo", {}).get("maxRank"),
            "BrRankPoint": data.get("basicInfo", {}).get("rankingPoints"),
            "CsMaxRank": data.get("basicInfo", {}).get("csMaxRank"),
            "CsRankPoint": data.get("basicInfo", {}).get("csRankingPoints"),
            "EquippedWeapon": data.get("basicInfo", {}).get("weaponSkinShows", []),
            "ReleaseVersion": data.get("basicInfo", {}).get("releaseVersion"),
            "ShowBrRank": data.get("basicInfo", {}).get("showBrRank"),
            "ShowCsRank": data.get("basicInfo", {}).get("showCsRank"),
            "Title": data.get("basicInfo", {}).get("title")
        },
        "AccountProfileInfo": {
            "EquippedOutfit": data.get("profileInfo", {}).get("clothes", []),
            "EquippedSkills": data.get("profileInfo", {}).get("equipedSkills", [])
        },
        "GuildInfo": {
            "GuildCapacity": data.get("clanBasicInfo", {}).get("capacity"),
            "GuildID": str(data.get("clanBasicInfo", {}).get("clanId")) if data.get("clanBasicInfo", {}).get("clanId") else None,
            "GuildLevel": data.get("clanBasicInfo", {}).get("clanLevel"),
            "GuildMember": data.get("clanBasicInfo", {}).get("memberNum"),
            "GuildName": data.get("clanBasicInfo", {}).get("clanName"),
            "GuildOwner": str(data.get("clanBasicInfo", {}).get("captainId")) if data.get("clanBasicInfo", {}).get("captainId") else None
        },
        "captainBasicInfo": {
            "EquippedWeapon": data.get("captainBasicInfo", {}).get("weaponSkinShows", []),
            "accountId": str(data.get("captainBasicInfo", {}).get("accountId")) if data.get("captainBasicInfo", {}).get("accountId") else None,
            "accountType": data.get("captainBasicInfo", {}).get("accountType"),
            "badgeCnt": data.get("captainBasicInfo", {}).get("badgeCnt"),
            "badgeId": str(data.get("captainBasicInfo", {}).get("badgeId")) if data.get("captainBasicInfo", {}).get("badgeId") else None,
            "bannerId": str(data.get("captainBasicInfo", {}).get("bannerId")) if data.get("captainBasicInfo", {}).get("bannerId") else None,
            "createAt": str(data.get("captainBasicInfo", {}).get("createAt")) if data.get("captainBasicInfo", {}).get("createAt") else None,
            "csMaxRank": data.get("captainBasicInfo", {}).get("csMaxRank"),
            "csRank": data.get("captainBasicInfo", {}).get("csMaxRank"),
            "csRankingPoints": data.get("captainBasicInfo", {}).get("csRankingPoints"),
            "exp": data.get("captainBasicInfo", {}).get("exp"),
            "headPic": str(data.get("captainBasicInfo", {}).get("headPic")) if data.get("captainBasicInfo", {}).get("headPic") else None,
            "lastLoginAt": str(data.get("captainBasicInfo", {}).get("lastLoginAt")) if data.get("captainBasicInfo", {}).get("lastLoginAt") else None,
            "level": data.get("captainBasicInfo", {}).get("level"),
            "liked": data.get("captainBasicInfo", {}).get("liked"),
            "maxRank": data.get("captainBasicInfo", {}).get("maxRank"),
            "nickname": data.get("captainBasicInfo", {}).get("nickname"),
            "rank": data.get("captainBasicInfo", {}).get("maxRank"),
            "rankingPoints": data.get("captainBasicInfo", {}).get("rankingPoints"),
            "region": data.get("captainBasicInfo", {}).get("region"),
            "releaseVersion": data.get("captainBasicInfo", {}).get("releaseVersion"),
            "seasonId": data.get("captainBasicInfo", {}).get("seasonId"),
            "showBrRank": data.get("captainBasicInfo", {}).get("showBrRank"),
            "showCsRank": data.get("captainBasicInfo", {}).get("showCsRank"),
            "title": data.get("captainBasicInfo", {}).get("title")
        },
        "creditScoreInfo": {
            "creditScore": data.get("creditScoreInfo", {}).get("creditScore"),
            "periodicSummaryEndTime": str(data.get("creditScoreInfo", {}).get("periodicSummaryEndTime")) if data.get("creditScoreInfo", {}).get("periodicSummaryEndTime") else None,
            "periodicSummaryStartTime": str(data.get("creditScoreInfo", {}).get("periodicSummaryStartTime")) if data.get("creditScoreInfo", {}).get("periodicSummaryStartTime") else None
        },
        "petInfo": data.get("petInfo", {}),
        "socialinfo": {
            "AccountLanguage": data.get("socialInfo", {}).get("language"),
            "AccountPreferMode": data.get("socialInfo", {}).get("modePrefer"),
            "AccountSignature": data.get("socialInfo", {}).get("signature")
        }
    }

# === API Routes ===
@app.route('/info')
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')
    key = request.args.get('key')
    if not uid or not region or not key:
        return jsonify({"error": "Please provide uid, region and the api key."}), 400
    if key !="TOC":
        return jsonify({"error": "invalid key. Please provide correct api key."}), 400
    try:
        return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        formatted = format_response(return_data)
        return jsonify(return_data), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400
        

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {str(e)}'}), 500

@app.route('/token-status')
def token_status():
    """Check status of cached tokens"""
    status = {}
    current_time = time.time()
    for region, info in cached_tokens.items():
        status[region] = {
            'exists': True,
            'expires_in': max(0, int(info['expires_at'] - current_time)),
            'server_url': info['server_url']
        }
    return jsonify(status), 200

# === Startup ===
async def startup():
    print("Starting application...")
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())
    print("Application started successfully!")

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5000, debug=True)
