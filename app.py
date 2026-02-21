
import os
from datetime import datetime, timezone
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FloatField
from wtforms.fields import DateTimeLocalField
from wtforms.validators import DataRequired, Length, Email, EqualTo, NumberRange, Optional

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    assignments = db.relationship("Assignment", backref="user", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    deadline = db.Column(db.DateTime(timezone=True), nullable=False)
    estimated_hours = db.Column(db.Float, nullable=False)
    is_finished = db.Column(db.Boolean, default=False)
    finished_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def deadline_status(self):
        now = datetime.now(timezone.utc)
        if self.is_finished:
            return "finished"
        if self.deadline < now:
            return "overdue"
        return "ok"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class RegisterForm(FlaskForm):
    name = StringField("Full name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm = PasswordField("Confirm password", validators=[EqualTo("password")])
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")


class AssignmentForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    description = TextAreaField("Description", validators=[Optional()])
    deadline = DateTimeLocalField("Deadline", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    estimated_hours = FloatField("Estimated hours", validators=[DataRequired(), NumberRange(min=0.25)])
    submit = SubmitField("Save")


def to_utc(dt_local):
    return datetime.fromtimestamp(dt_local.timestamp(), tz=timezone.utc)


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    assignments = Assignment.query.filter_by(user_id=current_user.id, is_finished=False).all()
    return render_template("dashboard.html", assignments=assignments)


@app.route("/finished")
@login_required
def finished():
    assignments = Assignment.query.filter_by(user_id=current_user.id, is_finished=True).all()
    return render_template("finished.html", assignments=assignments)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already exists")
            return redirect(url_for("login"))
        user = User(email=form.email.data, name=form.name.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/assignment/new", methods=["GET", "POST"])
@login_required
def new_assignment():
    form = AssignmentForm()
    if form.validate_on_submit():
        assignment = Assignment(
            user_id=current_user.id,
            title=form.title.data,
            description=form.description.data,
            deadline=to_utc(form.deadline.data),
            estimated_hours=form.estimated_hours.data
        )
        db.session.add(assignment)
        db.session.commit()
        return redirect(url_for("dashboard"))
    return render_template("assignment_form.html", form=form)


@app.route("/assignment/<int:id>/finish", methods=["POST"])
@login_required
def finish_assignment(id):
    assignment = db.session.get(Assignment, id)
    if assignment.user_id != current_user.id:
        abort(403)
    assignment.is_finished = True
    assignment.finished_at = datetime.now(timezone.utc)
    db.session.commit()
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
