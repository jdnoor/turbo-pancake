from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///coupons.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Coupon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True)
    value = db.Column(db.Integer)
    used = db.Column(db.Boolean, default=False)
    redeemed_at = db.Column(db.DateTime)
    redeemed_by = db.Column(db.Integer)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('redeem'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/redeem', methods=['GET', 'POST'])
@login_required
def redeem():
    if request.method == 'POST':
        code = request.form['code'].strip().upper()
        coupon = Coupon.query.filter_by(code=code).first()
        
        if not coupon:
            flash('Invalid coupon code', 'danger')
        elif coupon.used:
            flash('ERROR: Code USED', 'error')
        else:
            coupon.used = True
            coupon.redeemed_at = datetime.utcnow()
            coupon.redeemed_by = current_user.id
            db.session.commit()
            flash(f'Valid coupon! Value: {coupon.value}', 'success')
        return redirect(url_for('redeem'))
    
    return render_template('redeem.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///coupons.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Coupon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True)
    value = db.Column(db.Integer)
    used = db.Column(db.Boolean, default=False)
    redeemed_at = db.Column(db.DateTime)
    redeemed_by = db.Column(db.Integer)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('redeem'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/redeem', methods=['GET', 'POST'])
@login_required
def redeem():
    if request.method == 'POST':
        code = request.form['code'].strip().upper()
        coupon = Coupon.query.filter_by(code=code).first()
        
        if not coupon:
            flash('Invalid coupon code', 'danger')
        elif coupon.used:
            flash('ERROR: Code USED', 'error')
        else:
            coupon.used = True
            coupon.redeemed_at = datetime.utcnow()
            coupon.redeemed_by = current_user.id
            db.session.commit()
            flash(f'Valid coupon! Value: {coupon.value}', 'success')
        return redirect(url_for('redeem'))
    
    return render_template('redeem.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
