from flask import Flask,jsonify,request,make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'postgresql://arpitsangotra:@localhost:5432/bank'
db = SQLAlchemy(app)

class Banks(db.Model):
    id = db.Column(db.BigInteger,primary_key=True)
    name = db.Column(db.String(49))
    orders = db.relationship('Branches',backref='Banks')

    def __init__(self,name):
        self.name = name

    def __repr__(self):
        return '<Bank %r>' % self.name

class Branches(db.Model):
    ifsc = db.Column(db.String(11),primary_key=True,nullable=False)
    bank_id = db.Column(db.BigInteger,db.ForeignKey(Banks.id))
    branch = db.Column(db.String(74))
    address = db.Column(db.String(195))
    city = db.Column(db.String(50))
    district = db.Column(db.String(50))
    state = db.Column(db.String(26))

class User_db(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, str(app.config['SECRET_KEY']))
            current_user = User_db.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/',methods=['GET'])
def hello():
    return jsonify({'message' : 'Hello World'})


'''Manipulating the users'''
@app.route('/user',methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'],method = 'sha256')
    new_user = User_db(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})

@app.route('/user/<public_id>',methods=['PUT'])
def promote_user(public_id):
    user = User_db.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'No user found!'})
    user.admin = True
    db.session.commit()
    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
def delete_user(public_id):
    user = User_db.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/user',methods=['GET'])
def get_all_users():
    users = User_db.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users' : output}) 

@app.route('/user/<public_id>',methods=['GET'])
def get_one_user(public_id):
    user = User_db.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'messege':'User Not Found'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

'''JWT TOKEN'''
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User_db.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=5)}, str(app.config['SECRET_KEY']))

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


'''Main Functionality'''
@app.route('/bank',methods=['GET'])
@token_required
def branches(current_user):
    branch_inf = Branches.query.all()
    a=[]
    for branch_info in branch_inf:
        output={}
        output['ifsc'] = branch_info.ifsc
        a.append(output)
    return jsonify({'result':a})  

@app.route('/bank/<ifsc>',methods=['GET'])
@token_required
def get_bank_details(current_user,ifsc):
    branch_info = Branches.query.filter_by(ifsc=ifsc).first()
    if not branch_info:
        return jsonify({'messege':'Bank Not Found'})
    output={}
    output['branch'] = branch_info.branch
    output['address'] = branch_info.address
    output['city'] = branch_info.city
    output['district'] = branch_info.district
    output['state'] = branch_info.state
    k = branch_info.bank_id

    bank_name = Banks.query.filter_by(id=k).first()
    output['name'] = bank_name.name
    return jsonify({'result':output}) 

@app.route('/bank/<name>/<city>/<int:limit>/<int:offset>',methods=['GET'])
@token_required
def get_branch_details(current_user,name,city,limit,offset):
    bank_details = Banks.query.filter_by(name=name).first()
    if not bank_details:
        return jsonify({'messege':'Bank Not Found'})  #all names are unique
    k = bank_details.id

    mni = Branches.query.filter_by(city=city).filter_by(bank_id=k).offset(offset).limit(limit).all()

    if not mni:
        return jsonify({'messeges':'Bank Not Found'})            
    
    output=[]
    for mno in mni:
        dic = {}
        dic['name'] = name
        dic['district'] = mno.district
        dic['state'] = mno.state
        dic['branch'] = mno.branch
        dic['address'] = mno.address
        dic['ifsc'] = mno.ifsc
        output.append(dic)
        
    #return str(len(mni))
    return jsonify({'result':output})

@app.route('/bank/<name>/<city>',methods=['GET'])
@token_required
def get_branch_details_wolo(current_user,name,city):
    bank_details = Banks.query.filter_by(name=name).first()
    if not bank_details:
        return jsonify({'messege':'Bank Not Found'})  #all names are unique
    k = bank_details.id

    mni = Branches.query.filter_by(city=city).filter_by(bank_id=k).all()

    if not mni:
        return jsonify({'messeges':'Bank Not Found'})            
    
    output=[]
    for mno in mni:
        dic = {}
        dic['name'] = name
        dic['district'] = mno.district
        dic['state'] = mno.state
        dic['branch'] = mno.branch
        dic['address'] = mno.address
        dic['ifsc'] = mno.ifsc
        output.append(dic)
        
    #return str(len(mni))
    return jsonify({'result':output})    




if __name__ == "__main__":
    app.run(debug=True)
