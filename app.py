from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()

basedir = Path(__file__).resolve().parent

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + str(basedir / "vibely.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = str(basedir / "static" / "uploads")
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = "qevra101@gmail.com"
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = "qevra101@gmail.com"

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "mp4", "mov", "avi", "mkv"}


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.String(160), default="")
    profile_pic = db.Column(db.String(255), default="default.jpg")
    location = db.Column(db.String(120), default="")
    website = db.Column(db.String(255), default="")
    member_since = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship("Post", backref="author", lazy=True)
    followers = db.relationship("Follow", foreign_keys="Follow.followed_id", backref="followed_user", lazy=True)
    following = db.relationship("Follow", foreign_keys="Follow.follower_id", backref="follower_user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_following(self, user):
        return Follow.query.filter_by(follower_id=self.id, followed_id=user.id).first() is not None

    def get_reset_token(self, expires_sec=3600):
        return serializer.dumps(self.email, salt="reset-password")

    @staticmethod
    def verify_reset_token(token, expires_sec=3600):
        try:
            email = serializer.loads(token, salt="reset-password", max_age=expires_sec)
        except Exception:
            return None
        return User.query.filter_by(email=email).first()


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    media = db.Column(db.String(255), default="")
    media_type = db.Column(db.String(10), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    likes = db.relationship("Like", backref="post", lazy=True, cascade="all, delete-orphan")
    comments = db.relationship("Comment", backref="post", lazy=True, cascade="all, delete-orphan")


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(280), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    commenter = db.relationship("User")


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)
    text = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=True)


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Create account")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data.lower()).first():
            raise ValidationError("Username already taken")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError("Email already registered")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send reset link")


class ResetPasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField("Confirm New Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Reset password")


class PostForm(FlaskForm):
    text = TextAreaField("Write a post", validators=[DataRequired(), Length(max=500)])
    submit = SubmitField("Post")


class MessageForm(FlaskForm):
    text = TextAreaField("Message", validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField("Send")


class EditProfileForm(FlaskForm):
    bio = TextAreaField("Bio", validators=[Length(max=160)])
    location = StringField("Location", validators=[Length(max=120)])
    website = StringField("Website", validators=[Length(max=255)])
    profile_pic = FileField("Profile Picture", validators=[FileAllowed(["jpg", "jpeg", "png", "gif", "webp"], "Images only!")])
    submit = SubmitField("Save changes")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def media_type_for(filename):
    ext = filename.rsplit(".", 1)[1].lower()
    return "image" if ext in {"png", "jpg", "jpeg", "gif", "webp"} else "video"


def add_notification(user_id, actor_id, type_, text, post_id=None):
    note = Notification(
        user_id=user_id,
        actor_id=actor_id,
        type=type_,
        text=text,
        post_id=post_id
    )
    db.session.add(note)
    return note


def send_reset_email(user):
    token = user.get_reset_token()
    link = url_for("reset_password", token=token, _external=True)
    msg = Message(
        subject="Vibely Password Reset",
        recipients=[user.email],
        sender=app.config["MAIL_DEFAULT_SENDER"]
    )
    msg.body = f"""To reset your password, visit this link:

{link}

If you did not make this request, ignore this email.
"""
    mail.send(msg)


@app.context_processor
def inject_globals():
    unread_count = 0
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).count()
    return {"brand_name": "Vibely", "unread_count": unread_count}


@app.route("/")
def index():
    return redirect(url_for("index_home")) if current_user.is_authenticated else redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data.lower(), email=form.email.data.lower())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for("index_home"))
        flash("Invalid email or password")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            send_reset_email(user)
        flash("If the email exists, a reset link has been sent.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html", form=form)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash("Invalid or expired reset link.", "warning")
        return redirect(url_for("forgot_password"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash("Password updated successfully.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", form=form)


@app.route("/home", methods=["GET", "POST"])
@login_required
def index_home():
    form = PostForm()
    if form.validate_on_submit():
        media = request.files.get("media")
        filename = ""
        mt = ""
        if media and media.filename:
            if not allowed_file(media.filename):
                flash("Unsupported file type")
                return redirect(url_for("index_home"))
            filename = secure_filename(media.filename)
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            media.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            mt = media_type_for(filename)

        post = Post(text=form.text.data, media=filename, media_type=mt, author=current_user)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for("index_home"))

    posts = Post.query.order_by(Post.created_at.desc()).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return render_template("home.html", form=form, posts=posts, unread_count=unread_count)


@app.route("/profile/<username>")
@login_required
def profile(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.created_at.desc()).all()
    return render_template("profile.html", user=user, posts=posts)


@app.route("/edit-profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    form = EditProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.bio = form.bio.data
        current_user.location = form.location.data
        current_user.website = form.website.data
        pic = form.profile_pic.data
        if pic and pic.filename:
            filename = secure_filename(pic.filename)
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            pic.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            current_user.profile_pic = filename

        db.session.commit()
        flash("Profile updated")
        return redirect(url_for("profile", username=current_user.username))
    return render_template("edit_profile.html", form=form)


@app.route("/follow/<username>", methods=["POST"])
@login_required
def follow(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    if user.id != current_user.id and not current_user.is_following(user):
        db.session.add(Follow(follower_id=current_user.id, followed_id=user.id))
        add_notification(user_id=user.id, actor_id=current_user.id, type_="follow", text=f"@{current_user.username} started following you.")
        db.session.commit()
    return redirect(url_for("profile", username=username))


@app.route("/unfollow/<username>", methods=["POST"])
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    follow = Follow.query.filter_by(follower_id=current_user.id, followed_id=user.id).first()
    if follow:
        db.session.delete(follow)
        db.session.commit()
    return redirect(url_for("profile", username=username))


@app.route("/like/<int:post_id>", methods=["POST"])
@login_required
def like(post_id):
    post = Post.query.get_or_404(post_id)
    existing = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(Like(user_id=current_user.id, post_id=post.id))
        if post.user_id != current_user.id:
            add_notification(user_id=post.user_id, actor_id=current_user.id, type_="like", text=f"@{current_user.username} liked your post.", post_id=post.id)
    db.session.commit()
    return redirect(request.referrer or url_for("index_home"))


@app.route("/comment/<int:post_id>", methods=["POST"])
@login_required
def comment(post_id):
    post = Post.query.get_or_404(post_id)
    text = request.form.get("text", "").strip()
    if text:
        db.session.add(Comment(text=text, user_id=current_user.id, post_id=post.id))
        if post.user_id != current_user.id:
            add_notification(user_id=post.user_id, actor_id=current_user.id, type_="comment", text=f"@{current_user.username} commented on your post.", post_id=post.id)
        db.session.commit()
    return redirect(request.referrer or url_for("index_home"))


@app.route("/trending")
@login_required
def trending():
    posts = Post.query.order_by(Post.created_at.desc()).limit(20).all()
    return render_template("trending.html", posts=posts)


@app.route("/notifications")
@login_required
def notifications():
    notes = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({"is_read": True})
    db.session.commit()
    return render_template("notifications.html", notes=notes, unread_count=0)


@app.route("/notifications/read", methods=["POST"])
@login_required
def mark_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({"is_read": True})
    db.session.commit()
    return redirect(url_for("notifications"))


@app.route("/messages")
@login_required
def messages_list():
    users = User.query.filter(User.id != current_user.id).order_by(User.username.asc()).all()
    return render_template("messages_list.html", users=users)


@app.route("/messages/<username>", methods=["GET", "POST"])
@login_required
def messages(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    form = MessageForm()
    if form.validate_on_submit():
        db.session.add(ChatMessage(sender_id=current_user.id, receiver_id=user.id, text=form.text.data))
        db.session.commit()
        return redirect(url_for("messages", username=username))

    chats = ChatMessage.query.filter(
        ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == user.id)) |
        ((ChatMessage.sender_id == user.id) & (ChatMessage.receiver_id == current_user.id))
    ).order_by(ChatMessage.created_at.asc()).all()

    return render_template("messages.html", form=form, user=user, chats=chats)


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip().lower()
    users = User.query.filter(User.username.contains(q)).all() if q else []
    posts = Post.query.filter(Post.text.contains(q)).all() if q else []
    return render_template("search.html", q=q, users=users, posts=posts)


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)