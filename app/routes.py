from app import db, bcrypt
from app.forms import RegistrationForm, LoginForm, RequestForm, MessageForm, ClassMessageForm, AddSolutionForm
from app.models import User, Request, Solution, Message, Notification  # Include Notification model
from flask_login import login_user, current_user, logout_user, login_required
from flask import render_template, url_for, flash, redirect, request
import re


def create_notification(user_id, message, link=None):
    notification = Notification(user_id=user_id, message=message, link=link)
    db.session.add(notification)
    db.session.commit()



def register_routes(app):
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        else:
            return redirect(url_for('login'))

    @app.route("/register", methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        form = RegistrationForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, password_hash=hashed_password, role=form.role.data)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('login'))
        return render_template('register.html', title='Register', form=form)

    @app.route("/login", methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(user, remember=True)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
        return render_template('login.html', title='Login', form=form)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'success')
        return redirect(url_for('login'))

    @app.route("/home")
    @login_required
    def home():
        messages = []
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(
            Notification.timestamp.desc()).all()

        if current_user.role == 'Student':
            messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).all()
            messages = [
                {
                    'sender': User.query.get(message.sender_id).username,
                    'content': message.content,
                    'timestamp': message.timestamp
                }
                for message in messages
            ]
        return render_template('home.html', title='Home', messages=messages, notifications=notifications)

    def check_simple_solution(description):
        simple_solutions = {
            r'reset password': 'To reset your password, click on the "Forgot Password" link on the login page.',
            r'install python': 'To install Python, visit the official Python website and download the installer for your operating system.',
            r'how to compile java': 'To compile a Java program, use the `javac` command followed by the file name. Example: `javac MyProgram.java`.',
            r'install a library in python': 'To install a library in Python, use the `pip` command. Example: `pip install library_name`.',
            r'java version check': 'To check your Java version, open a command prompt and type `java -version`.',
            r'python version check': 'To check your Python version, open a command prompt and type `python --version` or `python3 --version`.',
            r'create virtual environment python': 'To create a virtual environment in Python, use the command `python -m venv env_name`.',
            r'activate virtual environment python': 'To activate a virtual environment in Python, use the command `source env_name/bin/activate` on macOS/Linux or `env_name\\Scripts\\activate` on Windows.'
        }

        for pattern, solution in simple_solutions.items():
            if re.search(pattern, description, re.IGNORECASE):
                return solution
        return None

    @app.route("/submit_request", methods=['GET', 'POST'])
    @login_required
    def submit_request():
        form = RequestForm()
        if form.validate_on_submit():
            description = form.description.data
            simple_solution = check_simple_solution(description)

            new_request = Request(
                user_id=current_user.id,
                topic=form.topic.data,
                urgency=form.urgency.data,
                description=description,
                module=form.module.data,
                machine_position=form.machine_position.data
            )
            db.session.add(new_request)
            db.session.commit()

            create_notification(current_user.id, 'Your request has been submitted.')

            if simple_solution:
                flash(f'Simple Solution: {simple_solution}', 'info')
                new_request.status = 'Resolved'
                db.session.commit()
                create_notification(current_user.id, 'Your request has been resolved with a simple solution.')
                return redirect(url_for('home'))

            flash('Your request has been submitted!', 'success')
            return redirect(url_for('home'))
        return render_template('submit_request.html', title='Submit Request', form=form)

    @app.route("/manage_requests")
    @login_required
    def manage_requests():
        if current_user.role not in ['GLA', 'Lecturer']:
            flash('You do not have access to this page.', 'danger')
            return redirect(url_for('home'))

        requests = Request.query.order_by(Request.created_at.desc()).all()

        for req in requests:
            if req.urgency == "I’m stuck":
                req.color = "red"
            elif req.urgency == "I can work around for now":
                req.color = "yellow"
            else:
                req.color = "green"

        return render_template('manage_requests.html', title='Manage Requests', requests=requests)

    @app.route("/add_solution/<int:request_id>", methods=['GET', 'POST'])
    @login_required
    def add_solution(request_id):
        if current_user.role not in ['GLA', 'Lecturer']:
            flash('You do not have access to this page.', 'danger')
            return redirect(url_for('home'))

        form = AddSolutionForm()
        if form.validate_on_submit():
            pattern = form.pattern.data
            solution_text = form.solution_text.data
            new_solution = Solution(pattern=pattern, solution_text=solution_text,
                                    request_id=request_id)
            db.session.add(new_solution)
            db.session.commit()
            flash('Solution has been added!', 'success')

            request_item = Request.query.get_or_404(request_id)
            link = url_for('view_solution', request_id=request_id)
            create_notification(request_item.user_id, 'A solution has been added to your request.', link=link)

            return redirect(url_for('manage_requests'))

        request_item = Request.query.get_or_404(request_id)
        form.request_id.data = request_item.id
        return render_template('add_solution.html', title='Add Solution', form=form, request=request_item)

    @app.route("/request/<int:request_id>/deal_with", methods=['POST'])
    @login_required
    def deal_with_request(request_id):
        req = Request.query.get_or_404(request_id)
        if current_user.role not in ['GLA', 'Lecturer']:
            flash('You do not have access to perform this action.', 'danger')
            return redirect(url_for('home'))
        req.status = 'Being Dealt With'
        req.assigned_to = current_user.id
        db.session.commit()
        flash('Request is now being dealt with', 'info')
        create_notification(req.user_id, 'Your request is being dealt with.')
        return redirect(url_for('manage_requests'))

    @app.route("/view_solution/<int:request_id>")
    @login_required
    def view_solution(request_id):
        request_item = Request.query.get_or_404(request_id)
        if request_item.user_id != current_user.id:
            flash('You do not have access to view this solution.', 'danger')
            return redirect(url_for('home'))
        solution = Solution.query.filter_by(request_id=request_id).first()
        return render_template('view_solution.html', title='View Solution', request=request_item, solution=solution)

    @app.route("/request/<int:request_id>/resolve", methods=['POST'])
    @login_required
    def resolve_request(request_id):
        req = Request.query.get_or_404(request_id)
        if current_user.role not in ['GLA', 'Lecturer']:
            flash('You do not have access to perform this action.', 'danger')
            return redirect(url_for('home'))
        req.status = 'Resolved'
        db.session.commit()
        flash('Request has been resolved', 'success')
        create_notification(req.user_id, 'Your request has been resolved.')
        return redirect(url_for('manage_requests'))

    @app.route("/send_message", methods=['GET', 'POST'])
    @login_required
    def send_message():
        form = MessageForm()
        form.receiver.choices = [(user.id, user.username) for user in User.query.filter_by(role='Student').all() if
                                 user.id != current_user.id]

        if form.validate_on_submit():
            if form.send_to_all.data:
                students = User.query.filter_by(role='Student').all()
                for student in students:
                    message = Message(
                        sender_id=current_user.id,
                        receiver_id=student.id,
                        content=form.content.data
                    )
                    db.session.add(message)
                flash('Message sent to all students!', 'success')
            else:
                message = Message(
                    sender_id=current_user.id,
                    receiver_id=form.receiver.data,
                    content=form.content.data
                )
                db.session.add(message)
                flash('Message sent!', 'success')

            try:
                db.session.commit()  # Commit the session directly
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('inbox'))

        return render_template('send_message.html', title='Send Message', form=form)

    @app.route("/inbox")
    @login_required
    def inbox():
        received_messages = Message.query.filter_by(receiver_id=current_user.id).order_by(
            Message.timestamp.desc()).all()
        sent_messages = Message.query.filter_by(sender_id=current_user.id).order_by(Message.timestamp.desc()).all()

        received_messages = [
            {
                'sender': User.query.get(message.sender_id).username,
                'receiver': User.query.get(message.receiver_id).username,
                'content': message.content,
                'timestamp': message.timestamp
            }
            for message in received_messages
        ]

        sent_messages_display = []
        for message in sent_messages:
            if message.receiver_id == 0:  # Assuming 0 indicates a message sent to all students
                receiver = "All Students"
            else:
                receiver = User.query.get(message.receiver_id).username
            sent_messages_display.append({
                'sender': User.query.get(message.sender_id).username,
                'receiver': receiver,
                'content': message.content,
                'timestamp': message.timestamp
            })

        return render_template('inbox.html', title='Inbox', received_messages=received_messages,
                               sent_messages=sent_messages_display)

    @app.route("/send_class_message", methods=['GET', 'POST'])
    @login_required
    def send_class_message():
        if current_user.role not in ['GLA', 'Lecturer']:
            flash('You do not have access to this page.', 'danger')
            return redirect(url_for('home'))
        form = ClassMessageForm()
        if form.validate_on_submit():
            students = User.query.filter_by(role='Student').all()
            for student in students:
                message = Message(
                    sender_id=current_user.id,
                    receiver_id=student.id,
                    content=form.content.data
                )
                db.session.add(message)
            db.session.commit()
            flash('Message sent to all students!', 'success')
            return redirect(url_for('inbox'))
        return render_template('send_class_message.html', title='Send Class Message', form=form)
