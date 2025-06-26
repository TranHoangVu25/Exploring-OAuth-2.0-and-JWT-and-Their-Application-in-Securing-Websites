from flask import Flask, request, redirect, render_template, url_for, make_response, abort, jsonify
import requests
import os
import jwt
import datetime
from dotenv import load_dotenv

load_dotenv()  
app = Flask(__name__)
JWT_SECRET = os.getenv('JWT_SECRET', os.urandom(24))
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXP = 20  # 20 giây - để demo nhanh
REFRESH_TOKEN_EXP = 60  # 60 giây - để demo nhanh

# Cấu hình Google OAuth
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
REDIRECT_URI = 'http://localhost:5000/callback'

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo"

def generate_jwt(payload, expiration, token_type='access'):
    """Tạo JWT token với thời gian hết hạn xác định"""
    payload_copy = payload.copy()
    payload_copy.update({
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration),
        'iat': datetime.datetime.utcnow(),
        'type': token_type
    })
    return jwt.encode(payload_copy, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt(token):
    """Giải mã JWT token với xử lý lỗi"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def get_current_user():
    """Lấy thông tin user từ JWT token"""
    access_token = request.cookies.get('access_token')
    if access_token:
        data = decode_jwt(access_token)
        if data and data.get('type') == 'access':
            return {
                'name': data.get('name'),
                'email': data.get('email'),
                'picture': data.get('picture'),
                'exp': data.get('exp')  # Thêm thời gian hết hạn
            }
    return None

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

    # Tạo payload cho tokens
    user_payload = {
        'name': userinfo.get('name', ''),
        'email': userinfo.get('email', ''),
        'picture': userinfo.get('picture', '')
    }

    # Tạo access token và refresh token
    access_token = generate_jwt(user_payload, ACCESS_TOKEN_EXP, 'access')
    refresh_token = generate_jwt({'email': userinfo['email']}, REFRESH_TOKEN_EXP, 'refresh')

    # Set cookies
    response = make_response(redirect(url_for('home')))
    response.set_cookie(
        'access_token',
        access_token,
        httponly=True,
        secure=False,
        samesite='Lax',
        max_age=ACCESS_TOKEN_EXP
    )
    response.set_cookie(
        'refresh_token',
        refresh_token,
        httponly=True,
        secure=False,
        samesite='Lax',
        max_age=REFRESH_TOKEN_EXP
    )
    return response

@app.route("/refresh", methods=['POST'])
def refresh_access_token():
    """Lấy access token mới bằng refresh token"""
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        abort(401, "Không tìm thấy refresh token")

    payload = decode_jwt(refresh_token)
    if not payload or payload.get('type') != 'refresh':
        abort(401, "Refresh token không hợp lệ")

    # Tạo access token mới
    access_token = generate_jwt(
        {'email': payload['email']}, 
        ACCESS_TOKEN_EXP, 
        'access'
    )

    # Trả về access token mới
    response = make_response(jsonify({
        'message': 'Token refreshed',
        'new_exp': (datetime.datetime.utcnow() + datetime.timedelta(seconds=ACCESS_TOKEN_EXP)).timestamp()
    }))
    response.set_cookie(
        'access_token',
        access_token,
        httponly=True,
        secure=False,
        samesite='Lax',
        max_age=ACCESS_TOKEN_EXP
    )
    return response

@app.route("/logout")
def logout():
    """Đăng xuất - xóa cả access token và refresh token"""
    response = make_response(redirect(url_for('home')))
    # Xóa cả access token và refresh token
    response.set_cookie('access_token', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)
    return response

@app.route("/api/protected")
def protected_api():
    """API bảo mật để demo"""
    user = get_current_user()
    if not user:
        abort(401)
    
    # Tính thời gian còn lại của token
    expires_at = user['exp']
    current_time = datetime.datetime.utcnow().timestamp()
    remaining = expires_at - current_time
    
    return jsonify({
        'message': 'Dữ liệu bảo mật!',
        'user': {
            'name': user['name'],
            'email': user['email']
        },
        'token_info': {
            'expires_at': expires_at,
            'remaining_seconds': round(remaining, 1) if remaining > 0 else 0
        }
    })

@app.route("/api/token-info")
def token_info_api():
    """API trả về thông tin token"""
    user = get_current_user()
    if not user:
        return jsonify({'status': 'not_authenticated'})
    
    # Tính thời gian còn lại của token
    expires_at = user['exp']
    current_time = datetime.datetime.utcnow().timestamp()
    remaining = expires_at - current_time
    
    return jsonify({
        'status': 'authenticated',
        'token_exp': expires_at,
        'remaining_seconds': round(remaining, 1) if remaining > 0 else 0
    })

if __name__ == "__main__":
    app.run(debug=True)