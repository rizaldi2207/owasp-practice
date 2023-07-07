import sqlite3
import secrets
import jwt
import datetime
from flask import Flask, request, make_response, jsonify, session

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
    payload = jwt.decode(token, key = secret_key, algorithms=['HS256',])
        
    return payload
    
def generate_jwt_token(userid, secret_key):
    
    # Define the payload
    payload = {
        'user_id': userid,
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
    def get_by_id(id):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_data WHERE id=?", (id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(user_data[1], user_data[2], user_data[3], user_data[4], user_data[5], user_data[6])
        return None

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
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = User.get_by_username(username)
    if user and user.password == password:
        #session_id = secrets.token_hex(16)
        #session['session_id'] = session_id
        #token = generate_jwt_token(user.username,jwt_secret)
        response  = make_response({'status': 200, 'message':'Login success'})
        #response.set_cookie('token', token)

        return response
    
    return jsonify({'message': 'Invalid username or password'})

@app.route('/protected', methods=['GET'])
def protected():
    #if 'session_id' in session:
        #token = request.cookies.get('token')
        #decode = validate_jwt_token(token, jwt_secret)
        #if decode:
        user_id = request.args.get('id') 
        user = User.get_by_id(user_id)
        return jsonify({'message': 'Access granted', 'user_data':{'username':user.username, 'firstname':user.firstname, 'phone':user.phone, 'address':user.address}})
        
        #else:
            #return jsonify({'message': 'Unauthorized'})
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

if __name__ == '__main__':
    create_table()
    app.run(host='192.168.119.132', port=5000, ssl_context='adhoc', debug=True)