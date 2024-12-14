# necessary library to work with app
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messaging.db' #  config to use database in SQLite
# app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key' # your secret 
app.config['JWT_SECRET_KEY'] = 'my_secret_key' # secret key  
db = SQLAlchemy(app) # using of SQLAlchemy library to manage database (messaging.db)
jwt = JWTManager(app)

# use to define and structure for table: user
# this is where table created: user
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# use to define and structure for table: message
# this is where table created: message
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_username = db.Column(db.String(80), nullable=False)
    receiver_username = db.Column(db.String(80), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# this is the route when you type in browser:
# https://127.0.0.1:500/ but this is render_template
# it will look for the current folder which is the folder "templates"
# inside the folder is the "chat-ui.html"
#  folder structure:
#
# python
# |
# +-- templates
# |   |
# |   +-- chat-ui.html <-- this is where the User Interface located
# |
# +-- app.py  <--  main python code mo
#
@app.route('/')
def home():
    return render_template('chat-ui.html')

#  this is URL that will use:
#  https://127.0.0.1:500/register  
# 
#  this is where chat-ui.html use to 
#  go into this code, 
#  whe you press the [register] button
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() # this will take info from the UI or placed by the user upon registration    
    # so in the data['username'] this is will get the info from the json data to pass in the HTML elements 
    # as well in the data['password']
    # this will be the content of object User named new_user
    new_user = User(username=data['username'], password=data['password'])
    # then add new_user that has info that will go in database session    
    db.session.add(new_user)
    #  db.session.commit() this will save in the database table: user
    db.session.commit()
    # it will return message in user of User register successfully.
    
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username'], password=data['password']).first()
    if user:
        access_token = create_access_token(identity=user.username)
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    response = jsonify({"message": "Successfully logged out"})
    unset_jwt_cookies(response)
    return response, 200

@app.route('/messages', methods=['POST'])
@jwt_required()
def send_message():
    sender_username = get_jwt_identity()
    data = request.get_json()
    new_message = Message(sender_username=sender_username, receiver_username=data['receiver_username'], content=data['content'])
    db.session.add(new_message)
    db.session.commit()
    return jsonify({"message": "Message sent"}), 200

@app.route('/messages/<receiver_username>', methods=['GET'])
@jwt_required()
def get_messages(receiver_username):
    sender_username = get_jwt_identity()
    messages = Message.query.filter(
        ((Message.sender_username == sender_username) & (Message.receiver_username == receiver_username)) |
        ((Message.sender_username == receiver_username) & (Message.receiver_username == sender_username))
    ).order_by(Message.timestamp.desc()).all()
    return jsonify([{
        'content': msg.content,
        'timestamp': msg.timestamp,
        'sender_username': msg.sender_username,
        'receiver_username': msg.receiver_username
    } for msg in messages]), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
