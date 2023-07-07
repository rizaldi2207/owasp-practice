import jwt
import datetime

def generate_jwt_token(userid, secret_key):
    
    # Define the payload
    payload = {
        'user_id': userid
    }
    
    # Generate the token
    token = jwt.encode(payload = payload, key=secret_key)
    
    return token

def validate_jwt_token(token, secret_key):
        # Decode the token
        payload = jwt.decode(token, key=secret_key, algorithms=['HS256',])
        
        return payload
    
token = generate_jwt_token('rizaldikocak', 'so_rahasia')
print(token)
decoded = validate_jwt_token(token, 'so_rahasia')
if decoded:
    print(decoded)
else:
    print('tidak valid')
    