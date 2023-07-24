import sqlite3
import secrets
import jwt
import datetime
import re
from flask import Flask, request, make_response, jsonify, session, render_template
import socket

hostname = socket.gethostname()
ipadd = socket.gethostbyname(hostname)

jwt_secret = 'FfUMdDbTrWqaKGucvcmI9jyXdGkt7QDftEQzkGT11eA'

app = Flask(__name__)
#app.secret_key = 'secret'
DB_NAME = 'auth_user.db'


def create_table():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS user_data
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL,
                      password TEXT NOT NULL,
                      first    TEXT NOT NULL,
                      last     TEXT NOT NULL,
                      phone    TEXT NOT NULL,
                      address  TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def validate_jwt_token(token, secret_key):
    # Decode the token
    try:
        payload = jwt.decode(token, key = secret_key, algorithms=['HS256',])
        
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    
def generate_jwt_token(userid, secret_key):
    
    # Define the payload
    payload = {
        'user_id': userid,
    }
    
    # Generate the token
    token = jwt.encode(payload = payload, key = secret_key)
    
    return token

def escape_special_characters(text):
    escaped_text = re.escape(text)
    return escaped_text

# User model
class User:
    def __init__(self, id, username, password, firstname, lastname, phone, address):
        self.id = id
        self.username = username
        self.password = password
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.address = address

    @staticmethod
    def save(username, password, firstname, lastname, phone, address):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user_data (username, password, first, last, phone, address) VALUES (?, ?, ?, ?, ?, ?)",
                       (username, password, firstname, lastname, phone, address))
        conn.commit()
        conn.close()

    def get_by_username(username):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_data WHERE username=?", (username,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3], user_data[4], user_data[5], user_data[6])
        return None
    def get_by_id(id):
        
        #escaping special character
        data = escape_special_characters(id)
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        #Bind Parameter/Prepare Parameter
        #cursor.execute("SELECT * FROM user_data WHERE id=? LIMIT 1", (data,))

        #No Validation/Sanitation
        cursor.execute(f'SELECT * FROM user_data WHERE id={data}')
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3], user_data[4], user_data[5], user_data[6])
        return None

@app.route('/', methods=['GET'])
def index():
     return render_template('login.html')

@app.route('/home', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/charts', methods=['GET'])
def charts():
    return render_template('charts.html')

@app.route('/tables', methods=['GET'])
def tables():
    return render_template('tables.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    firstname = data['firstname']
    lastname = data['lastname']
    phone = data['phone']
    address = data['address']
    if User.get_by_username(username):
        return jsonify({'message': 'Username already exists'})
    User.save(username, password, firstname, lastname, phone, address)
    return jsonify({'message':'Berhasil Register'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = User.get_by_username(username)
    if user and user.password == password:
        response  = make_response({'status': 200, 'message':'Login success', 'id':user.id})
        return response
    
    return jsonify({'message': 'Invalid username or password'})

@app.route('/protected', methods=['GET'])
def protected():
    user_id = request.args.get('id') 
    try:
        user = User.get_by_id(user_id)
        return jsonify({'message': 'Access granted', 'user_data':{'username':user.username, 'firstname':user.firstname, 'phone':user.phone, 'address':user.address}})
    except:
        return jsonify({'message':'Invalid Request', 'status code':400}), 400

@app.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('token')
    response  = make_response({'status': 200, 'message':'Logout success'})
    response.set_cookie('token', token, expires=0)

    return response

if __name__ == '__main__':
    create_table()
    app.run(host=ipadd, port=5000, ssl_context='adhoc', debug=True)