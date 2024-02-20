import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
from requests.auth import HTTPBasicAuth

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root@localhost:5432/clone123'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'qwertyui'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    last_login_time = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, nullable=False)
    urlsid = db.relationship('all_urls', backref='users')

    def __init__(self, username, password, is_admin=False):
        self.username = username
        self.password = password
        self.last_login_time = datetime.datetime.now()
        self.is_admin = is_admin


def insert_admin():
    user = User.query.filter_by(id=1).first()
    if user is None:
        admin_entry = User(username='admin', password='password', is_admin=False)
        db.session.add(admin_entry)
        db.session.commit()


class all_urls(db.Model):
    __tablename__ = 'all_urls'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(360), nullable=False)
    username = db.Column(db.String(200))
    password = db.Column(db.String(200))
    userid = db.Column(db.Integer, db.ForeignKey('users.id'))


@login_manager.user_loader
def load_user(user_id):
    x = User.query.get(int(user_id))
    if x == None:
        x = 1
    return x


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['POST', 'GET'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password, is_admin=False).first()
        if user:
            login_user(user)
            user.last_login_time = datetime.datetime.now()
            db.session.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    return render_template('User_login.html')


@app.route('/user_dashboard', methods=['GET'])
@login_required
def user_dashboard():
    url_details1 = all_urls.query.filter(all_urls.userid == current_user.get_id()).all()
    url_details2 = all_urls.query.filter(all_urls.userid == 1).all()
    url_details3 = url_details1 + url_details2

    results = []
    for url_detail in url_details3:
        url = url_detail.url
        username = url_detail.username
        password = url_detail.password
        userid = url_detail.userid
        id = url_detail.id

        try:
            response = requests.get(url, auth=HTTPBasicAuth(username, password))
            is_valid = response.ok
        except requests.RequestException:
            is_valid = False

        results.append(
            {'url': url, 'username': username, 'password': password, 'isValid': is_valid, 'userid': userid, 'id': id})

    return render_template('user_dashboard.html', urlDetails=results)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return render_template('home.html')


@app.route('/admin_login', methods=['POST', 'GET'])
def admin_login():
    user = User.query.filter_by(id=1).first()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if user.username == username and user.password == password and user.is_admin == False:
            flash('Chanage default admin password', 'success')
            return redirect(url_for('change_admin_password'))  # update the admin pass

        elif user.username == username and user.password == password and user.is_admin == True:
            login_user(user)
            flash('login to admin dashboard successfully', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid Username or Password. Please try again.', 'error')
            return redirect(url_for('admin_login'))

    return render_template("admin_login.html", user=user.is_admin)


@app.route('/admin_dashboard/user_credentials/register_new_user', methods=['POST', 'GET'])
@login_required
def register_new_user():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            existing_user = User.query.filter_by(username=username).first()

            if existing_user:
                flash('Username already exists. Please choose a different one.', 'error')
            else:
                new_user = User(username=username, password=password)
                db.session.add(new_user)
                db.session.commit()
                flash('New User Added successful!', 'success')
                return redirect(url_for('register_new_user'))

        normal_users = User.query.filter(User.id != 1).all()
        return render_template('register_new_user.html', normal_users=normal_users)


@app.route('/admin_login/change_default_password', methods=['GET', 'POST'])
def change_admin_password():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(id=1, is_admin=True).first()
        if existing_user:
            flash('default password is changed please login with new admin password.', 'error')
        else:
            user = User.query.filter_by(id=1).first()
            user.is_admin = True
            user.username = username
            user.password = password
            db.session.commit()
            flash('default password is changed successful! Now login with new password', 'success')
            return redirect(url_for('admin_login'))
    return render_template("change_admin_password.html")

@app.route('/error_page')
def error_page():
    return render_template('error_page.html')


@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        action = request.form.get('action')
        user_ids = request.form.getlist('user_ids')

        if action == 'remove':
            try:
                for user_id in user_ids:
                    user = User.query.get(user_id)
                    db.session.delete(user)
                    db.session.commit()

                normal_users = User.query.all()
                if len(user_ids)==0:
                    flash('Select user first !!', 'error')
                else:
                    flash('Selected users removed successfully.', 'success')
            except Exception:
                return redirect(url_for('error_page'))
            return redirect(url_for('register_new_user', normal_users=normal_users))

        if action == 'removeurl':
            try:
                for user_id in user_ids:
                    user = all_urls.query.get(user_id)
                    db.session.delete(user)
                    db.session.commit()
                normal_URLS = all_urls.query.all()
                if len(user_ids)==0:
                    flash('Please Select first !!', 'error')
                else:
                    flash('Selected Urls removed successfully.', 'success')
            except Exception:
                return redirect(url_for('error_page'))
            return redirect(url_for('admin_dashboard', normal_URLS=normal_URLS))

    owner = db.session.query(all_urls, User).filter(User.id == all_urls.userid)
    return render_template('admin_dashboard.html', normal_URLS=owner)


@app.route('/admin_dashboard/add_credentials', methods=['POST', 'GET'])
@login_required
def add_credentials():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        try:
            url = request.form['url']
            username = request.form['username']
            password = request.form['password']
            existing_user = all_urls.query.filter_by(url=url, username=username, password=password).first()
        except Exception:
            return redirect(url_for('error_page'))
        if existing_user:
            flash('Credentials already exists. Please choose a different one.', 'error')
        else:
            manager1 = all_urls(url=url, username=username, password=password,
                                userid=current_user.get_id() if not None else 1)
            db.session.add(manager1)
            db.session.commit()
            flash('Credentials Added Successfully...', 'success')
            normal_URLS = db.session.query(all_urls, User).filter(User.id == all_urls.userid)
            return render_template('admin_dashboard.html', normal_URLS=normal_URLS)
    return render_template('add_user_credentials.html')

@app.route('/user_dashboard/add_own_credentials', methods=['GET', 'POST'])
@login_required
def add_own_credentials():
    if request.method == 'POST':
        url = request.form['url']
        username = request.form['username']
        password = request.form['password']
        existing_user = all_urls.query.filter_by(url=url, username=username, password=password).first()
        if existing_user:
            flash('Credentials already exists. Please choose a different one.', 'error')
        else:

            try:
                url = all_urls(url=url, username=username, password=password, userid=current_user.get_id())
                db.session.add(url)
                db.session.commit()
                flash('Credentials Added Successfully...', 'success')
                normal_URLS = all_urls.query.all()
            except Exception as e:
                return  redirect(url_for('error_page'))
            return render_template('add_own_credentials.html', normal_URLS=normal_URLS)
    return render_template('add_own_credentials.html')


@app.route('/login/user/remove_redentials', methods=['GET', 'POST'])
@login_required
def remove_own_credentials():
    if request.method == 'POST':
        action = request.form.get('action')
        user_ids = request.form.getlist('user_ids')

        if action == 'removeown':
            for user_id in user_ids:
                user = all_urls.query.get(user_id)
                db.session.delete(user)
                db.session.commit()
                flash('Selected users removed successfully.', 'success')
    return redirect(url_for('user_dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        insert_admin()
    app.run(debug=True)
