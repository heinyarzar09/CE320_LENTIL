from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required
from app import db, bcrypt
from app.forms import RegistrationForm, LoginForm, RequestForm, MessageForm, ClassMessageForm, AddSolutionForm
from app.models import User, Request, Solution, Message
import logging
import re

logging.basicConfig(level=logging.INFO)


def log_interaction(action, user, details=""):
    logging.info(f"Action: {action}, User: {user.username}, Details: {details}")


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
    
    @app.route("/manage_requests")
    @login_required
    def manage_requests():
        if current_user.role not in ['GLA', 'Lecturer']:
            flash('You do not have access to this page.', 'danger')
            return redirect(url_for('home'))

        requests = Request.query.order_by(Request.created_at.desc()).all()

        # Assigning colors based on urgency
        for req in requests:
            if req.urgency == "I’m stuck":
                req.color = "red"
            elif req.urgency == "I can work around for now":
                req.color = "yellow"
            else:
                req.color = "green"

        return render_template('manage_requests.html', title='Manage Requests', requests=requests)

    @app.route("/submit_request", methods=['GET', 'POST'])
    @login_required
    def submit_request():
        form = RequestForm()
        if form.validate_on_submit():
            description = form.description.data
            simple_solution = check_simple_solution(description)

            if simple_solution:
                flash(f'Simple Solution: {simple_solution}', 'info')
                # Store the simple solution to reuse later
                new_request = Request(
                    user_id=current_user.id,
                    topic=form.topic.data,
                    urgency=form.urgency.data,
                    description=description,
                    module=form.module.data,
                    machine_position=form.machine_position.data,
                    status='Resolved'  # Mark the request as resolved if solved via simple solution
                )
                db.session.add(new_request)
                db.session.commit()
                return redirect(url_for('home'))

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
            flash('Your request has been submitted!', 'success')
            return redirect(url_for('home'))
        return render_template('submit_request.html', title='Submit Request', form=form)

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
        return redirect(url_for('manage_requests'))

    @app.route("/request/<int:request_id>/resolve", methods=['POST'])
    @login_required
    def resolve_request(request_id): # Notifying
        req = Request.query.get_or_404(request_id)
        if current_user.role not in ['GLA', 'Lecturer']:
            flash('You do not have access to perform this action.', 'danger')
            return redirect(url_for('home'))
        req.status = 'Resolved'
        db.session.commit()
        flash('Request has been resolved', 'success')
        return redirect(url_for('manage_requests'))


