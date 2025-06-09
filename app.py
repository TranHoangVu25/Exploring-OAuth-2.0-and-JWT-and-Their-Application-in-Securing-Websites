from flask import Flask, request, redirect, render_template, url_for, make_response, abort
import requests
import os
import jwt
import datetime
from dotenv import load_dotenv
import json

load_dotenv()  

app = Flask(__name__)
JWT_SECRET = os.getenv('JWT_SECRET', os.urandom(24))
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600  # đơn vị giây

# Cấu hình Google OAuth
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
REDIRECT_URI = 'http://localhost:5000/callback'

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo"

def generate_jwt(payload):
    payload_copy = payload.copy()
    payload_copy['exp'] = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    token = jwt.encode(payload_copy, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_jwt(token):
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return data
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def get_current_user():
    token = request.cookies.get('access_token')
    if not token:
        return None
    data = decode_jwt(token)
    if not data:
        return None
    return {
        'name': data.get('name'),
        'email': data.get('email'),
        'picture': data.get('picture')
    }

@app.route("/")
def home():
    user = get_current_user()
    if not user:
        return render_template('login.html')
    return render_template('customer.html', user=user)

@app.route("/login_gg")
def login():
    auth_url = (
        f"{GOOGLE_AUTH_ENDPOINT}?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        "response_type=code&"
        f"redirect_uri={REDIRECT_URI}&"
        "scope=openid%20email%20profile&"
        "access_type=offline&"
        "prompt=consent"
    )
    return redirect(auth_url)

@app.route("/callback")
def callback():
    code = request.args.get('code')
    if not code:
        abort(400, "Không nhận được mã xác thực")

    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    resp = requests.post(GOOGLE_TOKEN_ENDPOINT, data=token_data)
    token_json = resp.json()

    userinfo = requests.get(
        GOOGLE_USERINFO_ENDPOINT,
        headers={'Authorization': f'Bearer {token_json["access_token"]}'}
    ).json()

    # Tạo payload cho JWT
    payload = {
        'name': userinfo.get('name', ''),
        'email': userinfo.get('email', ''),
        'picture': userinfo.get('picture', '')
    }
    jwt_token = generate_jwt(payload)
    with open("token.json", "w") as f:
        json.dump({"access_token": jwt_token}, f)
    # Trả cookie cho client
    response = make_response(redirect(url_for('home')))
    response.set_cookie(
        'access_token',
        jwt_token,
        httponly=True,
        secure=False,    # True nếu chạy HTTPS
        samesite='Lax',
        max_age=JWT_EXP_DELTA_SECONDS
    )
    return response

@app.route("/logout")
def logout():
    response = make_response(redirect(url_for('home')))
    # gán hạn sử dụng = 0
    response.set_cookie('access_token', '', expires=0)
    return response

if __name__ == "__main__":
    app.run(debug=True)
