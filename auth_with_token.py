import sqlite3
import secrets
import jwt
import datetime
from flask import Flask, request, make_response, jsonify, session, render_template

jwt_secret = 'FfUMdDbTrWqaKGucvcmI9jyXdGkt7QDftEQzkGT11eA'

app = Flask(__name__)
#app.secret_key = 'secret'
DB_NAME = 'auth_user.db'


def create_table():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL,
                      password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def validate_jwt_token(token, secret_key):
    #try:
        # Decode the token
        payload = jwt.decode(token, key = secret_key, algorithms=['HS256',])
        
        # Check if the token is expired
        #if datetime.datetime.utcnow() > datetime.datetime.fromtimestamp(payload['exp']):
            #return None
        
        return payload
    
    #except jwt.ExpiredSignatureError:
        # Token has expired
        #return None
    
    #except jwt.InvalidTokenError:
        # Invalid token
        #return None
    
def generate_jwt_token(userid, secret_key):
    # Set the expiration time
    #expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiration_time_minutes)
    
    # Define the payload
    payload = {
        'user_id': userid,
        #'exp': expiration_time
    }
    
    # Generate the token
    token = jwt.encode(payload = payload, key = secret_key)
    
    return token

# User model
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def save(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (self.username, self.password))
        conn.commit()
        conn.close()

    @staticmethod
    def get_by_username(username):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(user_data[1], user_data[2])
        return None

#@app.route('/login', methods=['GET'])
#def index():
     #return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    if User.get_by_username(username):
        return jsonify({'message': 'Username already exists'})
    user = User(username, password)
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
        token = generate_jwt_token(user.username,jwt_secret)
        response  = make_response('Login success')
        response.set_cookie('token', token)

        return response
    
    return jsonify({'message': 'Invalid username or password'})

@app.route('/protected', methods=['GET'])
def protected():
    #if 'session_id' in session:
        token = request.cookies.get('token')
        decode = validate_jwt_token(token, jwt_secret)
        if decode:
            return jsonify({'message': 'Access granted', 'token': token, 'user':decode})
        
        else:
            return jsonify({'message': 'Unauthorized'})
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

             