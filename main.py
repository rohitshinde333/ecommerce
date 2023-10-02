from flask import Flask, render_template, request, url_for, redirect, flash, jsonify
from wtforms.fields import StringField, PasswordField, SubmitField, IntegerField, DateTimeField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, NumberRange ,DataRequired
from flask_restful import Resource, Api, marshal_with, reqparse, fields
from wtforms import StringField, TextAreaField, FloatField, IntegerField, SubmitField , DateField , SelectField
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from flask_wtf import FlaskForm
from functools import wraps
import os,sqlite3
from datetime import datetime



basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'Harishri@4444'
from flask_bcrypt import Bcrypt
db = SQLAlchemy(app)
myBcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()  
        if not current_user.is_admin:
            return redirect(url_for('dashboard'))  
        return func(*args, **kwargs)
    return decorated_view


#Database Model Definations
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    mail = db.Column(db.String(100), unique=True, nullable=False)
    passkey = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean)
    
    cart = db.relationship('Cart', back_populates='user', uselist=False)
    
    def __init__(self, username, mail, passkey, is_admin):
        self.username = username
        self.mail = mail
        self.passkey = passkey
        self.is_admin = is_admin

    def __repr__(self):
        return f'User {self.username}'

    
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    def __init__(self, name):
        self.name = name
    def __repr__(self):
        return f'{self.name}'

class Cart(db.Model):
    __tablename__ = 'cart'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    user = db.relationship('User', back_populates='cart')
    products = db.relationship('Product', secondary='cart_product_association', back_populates='carts')


cart_product_association = db.Table(
    'cart_product_association',
    db.Column('cart_id', db.Integer, db.ForeignKey('cart.id')),
    db.Column('product_id', db.Integer, db.ForeignKey('product.id'))
)

class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    mnfDate = db.Column(db.Date, nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    orders = db.relationship('Order', secondary='order_product_association', back_populates='products')
    category = db.relationship('Category', backref=db.backref('products', lazy=True))
    carts = db.relationship('Cart', secondary='cart_product_association', back_populates='products')

    def __init__(self, name, mnfDate, price, stock, category_id):
        self.name = name
        self.mnfDate = mnfDate
        self.price = price
        self.stock = stock
        self.category_id = category_id

    def __repr__(self):
        return f'Product {self.name},{self.mnfDate},{self.price},{self.category}'
    
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    shipping_add = db.Column(db.String(100), nullable=False)
    products = db.relationship('Product', secondary='order_product_association', back_populates='orders')

    def __repr__(self):
        return f'Order(id={self.id}, user_id={self.user_id}, order_date={self.order_date})'

order_product_association = db.Table(
    'order_product_association',
    db.Column('order_id', db.Integer, db.ForeignKey('order.id')),
    db.Column('product_id', db.Integer, db.ForeignKey('product.id')),
            
)
#Flask Forms 
class SignUpForm(FlaskForm):
    username = StringField('User Name', [InputRequired(),Length(min=3,max=50)],render_kw={"Placeholder":"User Name"})
    mail = StringField('Email Id', [InputRequired(),Length(min=3,max=50)],render_kw={"Placeholder":"Email ID"})
    passkey = StringField('Passkey', [InputRequired(),Length(min=8,max=20)],render_kw={"Placeholder":"Password"})
    is_admin = BooleanField('Admin')
    submit = SubmitField("SignUp")
    

class LoginForm(FlaskForm):
    mail = StringField('Email Id', [InputRequired(),Length(min=3,max=50)],render_kw={"Placeholder":"Email ID"})
    passkey = StringField('Passkey', [InputRequired(),Length(min=8,max=20)],render_kw={"Placeholder":"Password"})
    submit = SubmitField("Login")

class OrderForm(FlaskForm):
    shipping_add = StringField('Shipping_add', validators=[DataRequired()])
    submit = SubmitField('Order')

class AddCategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired()])
    submit = SubmitField('Add Category')

class UpdateCategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired()])
    submit = SubmitField('Update Category')

class AddProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    mnfDate = DateField('Manufacturing Date', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired()])
    category_id = IntegerField('Category ID', validators=[DataRequired()])
    submit = SubmitField('Add Product')

class UpdateProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    mnfDate = DateField('Manufacturing Date', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired()])
    category_id = IntegerField('Category ID', validators=[DataRequired()])
    submit = SubmitField('Update Product')


class SearchForm(FlaskForm):
    category = SelectField('Category', validators=[DataRequired()])
    min_price = FloatField('Min Price')
    max_price = FloatField('Max Price')
    mnfDate = DateField('Manufacturing Date', format='%Y-%m-%d')
    submit = SubmitField('Search')


@app.route('/')
def root():
    return render_template('root.html',user = None)

@app.route('/login',methods=['GET','POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(mail = login_form.mail.data).first()
        if user:
            if myBcrypt.check_password_hash(user.passkey, login_form.passkey.data):
                login_user(user)
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('home'))
            else:
                raise ValidationError('Incorrect Passkey!')
        else:
            raise ValidationError('User not found')        
    return render_template('login.html',form=login_form, user = None)

@app.route('/signup', methods=['GET','POST'])
def signup():
    signup_form = SignUpForm()
    if signup_form.validate_on_submit():
        passkey = myBcrypt.generate_password_hash(signup_form.passkey.data)
        new_user = User(username=signup_form.username.data, mail=signup_form.mail.data, passkey= passkey, is_admin=signup_form.is_admin.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=signup_form, user = None)

@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))



@app.route('/home',methods=['GET','POST'])
@login_required
def home():
    user = current_user
    products = Product.query.all()
    categories = Category.query.all()
    return render_template('home.html', user = user, products=products, categories=categories)

@app.route('/category/<int:category_id>')
@login_required
def category(category_id):
    category = Category.query.get_or_404(category_id)
    products = Product.query.filter_by(category=category).all()
    return render_template('category.html', category=category, products=products, user=current_user)



@app.route('/add_to_cart/<int:product_id>', methods=['POST','GET'])
@login_required
def add_to_cart(product_id):
    if current_user.is_authenticated:
        product = Product.query.get_or_404(product_id)
        user=current_user
        if user.cart is None:
            cart = Cart(user_id = current_user.id)
            db.session.add(cart)
            db.session.commit()
        else:
            
            cart = current_user.cart

            cart.products.append(product)
            db.session.commit()    
        return redirect(url_for('cart'))
    else:
        return redirect(url_for('login'))

@app.route('/cart')
@login_required
def cart():
    if current_user.is_authenticated and current_user.cart is not None:
        cart = current_user.cart
        products = cart.products  
        return render_template('cart.html', products=products, user=current_user)
    else:
        return redirect(url_for('login'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    form = OrderForm()

    if current_user.is_authenticated and current_user.cart is not None:
        cart = current_user.cart
        if request.method == 'POST':
            if form.validate_on_submit:

                new_order = Order(user=current_user,shipping_add = form.shipping_add.data)
                new_order.products = cart.products
                db.session.add(new_order)
                db.session.commit()
            
                cart.products.clear()
            
                return redirect(url_for('order_confirmation'))

        else:
            products = cart.products
            return render_template('checkout.html', products=products, user=current_user, form=form)
    else:
        return redirect(url_for('login'))

@app.route('/order_confirmation')
@login_required
def order_confirmation():
    return render_template('order_confirmation.html', user=current_user)


@app.route('/about',methods=['GET','POST'])
@login_required
def about():
    return render_template('about.html',user=current_user)

@app.route('/contact',methods=['GET','POST'])
@login_required
def contact():
    return render_template('contact.html',user=current_user)

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    products = Product.query.all()
    categories = Category.query.all()
    return render_template('admin_dashboard.html', user = current_user, products=products, categories=categories)

@app.route('/admin_add_category', methods=['GET', 'POST'])
@admin_required
def add_category():
    form = AddCategoryForm()
    if form.validate_on_submit():
        new_category = Category(name=form.name.data)
        db.session.add(new_category)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('add_category.html',form=form, user=current_user)

@app.route('/delete_category/<int:category_id>', methods=['GET','POST'])
@admin_required
def delete_category(category_id):
    cat_to_delete = Category.query.get(category_id)
    products_to_delete = Product.query.filter_by(category_id=cat_to_delete.id)
    for product in products_to_delete:
        db.session.delete(product)
        db.session.commit()
    db.session.delete(cat_to_delete)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/update_category/<int:category_id>', methods=['GET', 'POST'])
@admin_required
def update_category(category_id):
    category = Category.query.get_or_404(category_id)
    form = UpdateCategoryForm(obj=category)
    
    if form.validate_on_submit():
        form.populate_obj(category)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    
    return render_template('update_category.html', form=form, category=category, user=current_user)


@app.route('/admin_add_product', methods=['GET', 'POST'])
@admin_required
def add_product():
    form = AddProductForm()
    if form.validate_on_submit():
        
        new_product = Product(
            name=form.name.data,
            mnfDate=form.mnfDate.data,  
            price=form.price.data,
            stock=form.stock.data,
            category_id=form.category_id.data
        )
        
        
        db.session.add(new_product)
        db.session.commit()
        
        flash('Product added successfully!', 'success')  
        return redirect(url_for('admin_dashboard'))
    
    return render_template('add_product.html', form=form, user=current_user)




@app.route('/delete_products/<int:product_id>', methods=['GET','POST'])
@admin_required
def delete_product(product_id):
    product_to_delete = Product.query.get(product_id)
    db.session.delete(product_to_delete)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/update_product/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = UpdateProductForm(obj=product)
    
    if form.validate_on_submit():
        form.populate_obj(product)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    
    return render_template('update_product.html', form=form, product=product, user=current_user)


@app.route('/admin_orders')
@admin_required
def admin_orders():
    orders = Order.query.all()
    return render_template('admin_orders.html', orders=orders, user=current_user)

@app.route('/user_orders')
@login_required
def user_orders():
    orders = current_user.orders
    return render_template('user_orders.html', orders=orders, user=current_user)

@app.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    results = []

    all_categories = Category.query.distinct(Category.name).all()
    
    # Set the choices for the category field
    form.category.choices = [(category, category) for category in all_categories]
    
    
    if form.validate_on_submit():
        category_name = form.category.data
        min_price = form.min_price.data
        max_price = form.max_price.data
        manufacturing_date = form.mnfDate.data
        
        query = Product.query

        if category_name:
            category = Category.query.filter_by(name=category_name).first()
            if category:
                query = query.filter(Product.category.has(id=category.id))

        if min_price:
            query = query.filter(Product.price >= min_price)
        if max_price:
            query = query.filter(Product.price <= max_price)
        if manufacturing_date:
            query = query.filter(Product.mnfDate <= manufacturing_date)


        results = query.all()

    else:
        results = []

    # Fetch available categories from the database
    all_categories = Category.query.distinct(Category.name).all()

    # Set the choices for the category field
    form.category.choices = [(category.name, category.name) for category in all_categories]

    return render_template('search_results.html', form=form, results=results, user=current_user)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)