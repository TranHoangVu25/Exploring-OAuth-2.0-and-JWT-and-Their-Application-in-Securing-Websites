# from flask import Flask,request

# app = Flask(__name__)

# @app.route("/login")
# def login():
#     return request('login.html')

# def main():
#     app.run(debug=True)
from flask import Flask, request, redirect, session, render_template, url_for
import requests
import os
from dotenv import load_dotenv

load_dotenv()  # Load biến môi trường

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key cho session

# Cấu hình Google OAuth
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
REDIRECT_URI = 'http://localhost:5000/callback'

# Các endpoint của Google
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo"

@app.route("/")
# def home():
#     # Kiểm tra xem user đã đăng nhập chưa
#     if 'user' in session:
#         return f"Xin chào {session['user']['name']}! <a href='/logout'>Đăng xuất</a>"
#     return redirect(url_for('login'))
def home():
    if 'user' in session:
        return render_template('user.html')
    return render_template('login.html')


@app.route("/login")
def login():
    # Tạo URL xác thực Google
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
    # Xử lý authorization code
    code = request.args.get('code')
    
    if not code:
        return "Lỗi: Không nhận được mã xác thực", 400

    # Đổi code lấy access token
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    response = requests.post(GOOGLE_TOKEN_ENDPOINT, data=token_data)
    token_json = response.json()
    
    # Lấy thông tin người dùng
    userinfo = requests.get(
        GOOGLE_USERINFO_ENDPOINT,
        headers={'Authorization': f'Bearer {token_json["access_token"]}'}
    ).json()

    # Lưu thông tin người dùng vào session
    session['user'] = {
        'name': userinfo.get('name', ''),
        'email': userinfo.get('email', ''),
        'picture': userinfo.get('picture', '')
    }
    
    return redirect(url_for('home'))

@app.route("/logout")
def logout():
    # Xóa thông tin người dùng khỏi session
    session.pop('user', None)
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)