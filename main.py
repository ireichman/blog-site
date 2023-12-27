from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap as Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import sqlalchemy.exc
from functools import wraps


def is_admin():
    # Checking if user ID is 1. If so they are admin.
    try:
        if current_user.id == 1:
            user_admin = True
        else:
            user_admin = False
    except AttributeError as error:
        print(error)
        user_admin = False
    return user_admin


def admin_only(func):
    # Decorator which checks if the user has permissions to the resource.
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            if current_user.id == 1:
                user_admin = True
                return func(*args, **kwargs)
            else:
                return abort(403)
        except AttributeError as error:
            print(error)
            return abort(403)
        except Exception as error:
            print(error)
            return abort(403)
    wrapper.__name__ = func.__name__
    return wrapper


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Create Gravatar interaction.
gravatar = Gravatar(app,
                    size=100,
                    rating='x',
                    default='retro',
                    force_default=False)
@login_manager.user_loader
def load_user(user_id: int):
    return User.query.get(user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts3.db'
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(), nullable=False)
    # Create relationships between Users and their posts and comments.
    posts = db.relationship('BlogPost', back_populates="author")
    comments = db.relationship('Comment', back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Creating relationship between user in User database and the author in BlogPost
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship("User", back_populates="posts")
    comments = db.relationship('Comment', back_populates="comment_text")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comments = db.Column(db.Text, nullable=False)
    # Relationship between comment and user.
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    comment_text = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        print(register_form.data)
        secret_password = generate_password_hash(password=register_form.data["password"], method="pbkdf2:sha256", salt_length=16)
        try:
            with app.app_context():
                new_user = User(name=register_form.data["name"],
                                email=register_form.data["email"],
                                password=secret_password)
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for("get_all_posts"))
        except sqlalchemy.exc.IntegrityError as error:
            print(error)
            flash("User already exists")
            return redirect('login')
    return render_template("register.html", register_form=register_form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        with app.app_context():
            user = db.session.execute(db.Select(User).where(User.email == login_form.data["email"])).scalar()
            # Checking if the user name or password are incorrect.
            if not user:
                flash('User does not exist')
                return redirect(url_for('login'))
            elif not check_password_hash(user.password, login_form.data["password"]):
                flash("Wrong password")
                return redirect(url_for('login'))
            else:
                login_user(user=user)
                return redirect(url_for('get_all_posts'))
    return render_template("login.html", login_form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    users = db.session.execute(db.select(User)).scalars().all()
    logged_in = current_user.is_authenticated
    return render_template("index.html", all_posts=posts, logged_in=logged_in, user_admin=is_admin(),
                           users=users)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    logged_in = current_user.is_authenticated
    requested_post = db.get_or_404(BlogPost, post_id)
    comments_form = CommentForm()
    if comments_form.validate_on_submit():
        if logged_in:
            print(comments_form.data["comment"])
            print(current_user.id)
            new_comment = Comment(comments=comments_form.data["comment"],
                                  author_id=current_user.id,
                                  post_id=post_id)
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("Please log in to leave a comment")
            return redirect(url_for('login'))
    all_comments = db.session.execute(db.select(Comment).where(Comment.post_id == post_id)).scalars().all()
    return render_template("post.html", post=requested_post, logged_in=logged_in, user_admin=is_admin(),
                           comments_form=comments_form, all_comments=all_comments)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    logged_in = current_user.is_authenticated
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=logged_in)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    logged_in = current_user.is_authenticated
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=logged_in)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    logged_in = current_user.is_authenticated
    return render_template("about.html", logged_in=logged_in)


@app.route("/contact")
def contact():
    logged_in = current_user.is_authenticated
    return render_template("contact.html", logged_in=logged_in)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
