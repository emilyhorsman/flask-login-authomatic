from flask import Flask, abort, render_template, make_response, request, redirect, url_for
from flask.ext.login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from playhouse.flask_utils import FlaskDB
from peewee import CharField, DateField
from authomatic import Authomatic
from authomatic.adapters import WerkzeugAdapter
import config

# Configure the Flask application instance.
app = Flask(__name__)
app.config["DATABASE"]   = config.database
app.config["SECRET_KEY"] = config.flask_secret

# http://peewee.readthedocs.org/en/latest/peewee/playhouse.html#flask-utils
database = FlaskDB(app)

# http://flask-login.readthedocs.org/en/latest/#flask.ext.login.LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

# http://peterhudec.github.io/authomatic/reference/classes.html#authomatic.Authomatic
authomatic = Authomatic(config.authomatic_config, config.authomatic_secret)

# Super quick user model with peewee
class User(UserMixin, database.Model):
    auth = CharField(unique=True) # uid given by authomatic provider
    name = CharField(null=True)

@login_manager.user_loader
def load_user(uid):
    try:
        return User.get(User.id == uid)
    except User.DoesNotExist:
        return None

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        current_user.name = request.form["name"]
        current_user.save()

    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    # Redirect back to index if this action is accessed when already logged in.
    if current_user.is_authenticated():
        return redirect(url_for("index"))

    response = make_response()
    result = authomatic.login(WerkzeugAdapter(request, response), "tw")
    if result:
        if result.user:
            # authomatic
            result.user.update()

            # model
            user, created = User.get_or_create(auth=result.user.id)

            # flask-login
            login_user(user)

            return redirect(url_for("index"))

        if result.error:
            return "Error: {}".format(result.error.message)

        # Something really bad has happened.
        abort(500)

    return response

@app.route("/logout")
def logout():
    logout_user()
    return "Logged out."

if __name__ == "__main__":
    database.database.create_tables([User], safe=True)
    app.run(debug=True)
