from flask import Flask, request, make_response, session, render_template, redirect
from flask_login import LoginManager, login_user, login_required, logout_user

from data.users import User

from data import db_session
from forms.loginform import LoginForm
from forms.register import RegisterForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        user = User(
            name=form.name.data,
            email=form.email.data,
            about=form.about.data
        )
        user.set_password(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        return redirect('/login')
    return render_template('register.html', title='Регистрация', form=form)


@app.route("/cookie_test")
def cookie_test():
    visits_count = int(request.cookies.get("visits_count", 0))
    if visits_count:
        res = make_response(
            f"Вы пришли на эту страницу {visits_count + 1} раз")
        res.set_cookie("visits_count", str(visits_count + 1),
                       max_age=60 * 60 * 24 * 365 * 2)
    else:
        res = make_response(
            "Вы пришли на эту страницу в первый раз за последние 2 года")
        res.set_cookie("visits_count", '1',
                       max_age=60 * 60 * 24 * 365 * 2)
    return res


@app.route("/")
@app.route('/success')
def success():
    return render_template('success.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect('/success')
        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)


def main():
    db_session.global_init("db/blogs.db")
    db_sess = db_session.create_session()

    # user = User()
    # user.name = 'bubu'
    # user.about = "биография bubu"
    # user.email = "bubu@email.ru"
    # db_sess.add(user)
    # db_sess.commit()
    #
    # user = User()
    # user.name = 'bebe'
    # user.about = "биография bebe"
    # user.email = "bebe@email.ru"
    # db_sess.add(user)
    # db_sess.commit()
    #
    # user = User()
    # user.name = 'bibi'
    # user.about = "биография bibi"
    # user.email = "bibi@email.ru"
    # db_sess.add(user)
    # db_sess.commit()

    # user = User()
    # user.name = 'Фет А.'
    # user.about = "биография Фет А."
    # user.email = "fet@email.ru"
    # user.set_password('1234')
    # db_sess.add(user)
    # db_sess.commit()

    # for user in db_sess.query(User).all():
    #     print(user)
    app.run()


if __name__ == '__main__':
    main()
