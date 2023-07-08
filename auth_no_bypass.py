import sqlite3
import secrets
import jwt
import datetime
from flask import Flask, request, make_response, jsonify, session, render_template
from flask_cors import CORS
import socket

hostname = socket.gethostname()
ipadd = socket.gethostbyname(hostname)

jwt_secret = 'FfUMdDbTrWqaKGucvcmI9jyXdGkt7QDftEQzkGT11eA'

app = Flask(__name__)
CORS(app)
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
        
        #check exp
        if datetime.datetime.utcnow() > datetime.datetime.fromtimestamp(payload['exp']):
            return None
        
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    
def generate_jwt_token(userid, secret_key, expiration_time_minutes):

    #Expiration time
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiration_time_minutes)
    
    # Define the payload
    payload = {
        'user_id': userid,
        'exp': expiration_time
    }
    
    # Generate the token
    token = jwt.encode(payload = payload, key = secret_key)
    
    return token

# User model
class User:
    def __init__(self, username, password, firstname, lastname, phone, address):
        self.username = username
        self.password = password
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.address = address

    def save(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user_data (username, password, first, last, phone, address) VALUES (?, ?, ?, ?, ?, ?)",
                       (self.username, self.password, self.firstname, self.lastname, self.phone, self.address))
        conn.commit()
        conn.close()

    @staticmethod
    def get_by_username(username):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_data WHERE username=?", (username,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(user_data[1], user_data[2], user_data[3], user_data[4], user_data[5], user_data[6])
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
    user = User(username, password, firstname, lastname, phone, address)
    user.save()
    return jsonify({'message':'Berhasil Register'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    user = User.get_by_username(username)
    if user and user.password == password:
        #session_id = secrets.token_hex(16)
        #session['session_id'] = session_id
        token = generate_jwt_token(user.username,jwt_secret, 2)
        response  = make_response({'status': 200, 'message':'Login success'})
        response.set_cookie('token', token)

        return response
    
    return jsonify({'status': 401, 'message': 'Invalid username or password'})

@app.route('/protected', methods=['GET'])
def protected():
    #if 'session_id' in session:
        token = request.cookies.get('token')
        decode = validate_jwt_token(token, jwt_secret)
        if decode:
            user = User.get_by_username(decode['user_id'])
            return jsonify({'message': 'Access granted', 'token': token, 'user_data':{'username':user.username, 'firstname':user.firstname, 'phone':user.phone, 'address':user.address}})
        
        else:
            return jsonify({'message': 'Unauthorized'}), 401
        #try:
            #payload = jwt.decode(token, secret_key_validated, algorithm=['HS256'])

            #if 'user_id' in payload:
                #return jsonify({'message': 'Access granted', 'token': token})
            
            #return jsonify({'message': 'Unauthorized', 'token': token})
        
        #except jwt.ExpiredSignatureError:
            #return jsonify({'message': 'Token Expired', 'token': token})
        
        #except jwt.InvalidTokenError:
            #return jsonify({'message': 'Invalid Token', 'token': token})
        
    #return jsonify({'message': 'You are not logged in!'})

@app.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('token')
    response  = make_response({'status': 200, 'message':'Logout success'})
    response.set_cookie('token', token, expires=0)

    return response

if __name__ == '__main__':
    create_table()
    app.run(host=ipadd, port=5000, ssl_context='adhoc', debug=True)

#192.168.119.132             