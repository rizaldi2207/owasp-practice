import pyotp
import sqlite3
import hashlib
import uuid
from flask import Flask, request

app = Flask(__name__)

db_name = 'auth_user.db'

@app.route('/', methods=['GET'])
def index():
    home = {'Status' : '200,',
            'message' : 'Success'}
    return home

@app.route('/signup/v1', methods=['POST'])
def signup_v1():
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS USER_PLAIN (
            USERNAME    TEXT    PRIMARY KEY NOT NULL,
            PASSWORD    TEXT    NOT NULL
            );
    
    ''')
    conn.commit()
    try:
        c.execute("INSERT INTO USER_PLAIN (USERNAME,PASSWORD)"
                  "VALUES ('{0}','{1}')".format(request.form['username'],request.form['password']))
        conn.commit()
    except sqlite3.IntegrityError:
        data  = {
            'status' : '400',
            'message' : 'Failed to Register'
        }
        return data
    
    data_success = {
        'status' : '200',
        'message' : 'Register success'
    }
    return data_success

def verify_login(username, password):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    query = "SELECT PASSWORD FROM USER_PLAIN WHERE USERNAME = '{0}'".format(username)
    c.execute(query)
    records = c.fetchone()
    conn.close()
    if not records:
        return False
    return records[0] == password

@app.route('/login/v1', methods = ['GET','POST'])
def login_v1():
    if request.method == 'POST':
        if verify_login(request.form['username'], request.form['password']):
            msg = {
                'status' : '200',
                'message' : 'Login Success!!'
            }
            return msg
        else:
            msg_error = {
                'status' : '401',
                'message' : 'Invalid username or password'
            }
            return msg_error
    else:
        msg_error2 = {
            'status' : '400',
            'message' : 'Invalid HTTP Methods'
        }
        return msg_error2

if __name__ == '__main__':
    app.run(host='192.168.119.132', port=5000, ssl_context='adhoc', debug=True)