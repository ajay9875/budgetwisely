from calendar import month_name

from flask import Flask, render_template, request, session, flash, redirect, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
#from werkzeug.utils import never_cache
from email_validator import validate_email, EmailNotValidError
from datetime import datetime, timedelta
import random
import smtplib
import os
from dotenv import load_dotenv

import pymysql

pymysql.install_as_MySQLdb()

load_dotenv()

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY')

app.config['SESSION_PERMANENT'] = False  # Prevent session expiration issues

#app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions on the server

# Configure SQLAlchemy for Aiven PostgreSQL

# ✅ CORRECT (Tells SQLAlchemy to use PyMySQL)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {

    'pool_size': 10,
    'max_overflow': 20,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
    'pool_timeout': 30
}

db = SQLAlchemy(app)

# New DB Schemas for Python Anywhere MySQL server
# Create a db for pa db  withe this code as I wnat to connect pa mysql db 
# Database Models
class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserBudget(db.Model):
    __tablename__ = 'users_budget'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    month_name = db.Column(db.String(50), nullable=False)
    monthly_income = db.Column(db.Numeric(10, 2), nullable=False)
    total_expenses = db.Column(db.Numeric(10, 2))
    savings = db.Column(db.Numeric(10, 2))

    expenses = db.relationship('Expense', backref='budget', cascade='all, delete-orphan')

class Expense(db.Model):
    __tablename__ = 'expenses'

    id = db.Column(db.Integer, primary_key=True)
    budget_id = db.Column(
        db.Integer,
        db.ForeignKey('users_budget.id', ondelete='CASCADE'),
    )
    user_id = db.Column(db.Integer, nullable=False)
    day_name = db.Column(db.String(20), nullable=False)
    month_name = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)
    expense_category = db.Column(db.String(100), nullable=False)
    expense_amount = db.Column(db.Numeric(10, 2), nullable=False)

"""# Database Models
class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {'schema': 'auth_schema'}

    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserBudget(db.Model):
    __tablename__ = 'users_budget'
    __table_args__ = (
        db.UniqueConstraint('username', 'month_name', name='unique_user_month'),
        {'schema': 'budget_schema'}
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    month_name = db.Column(db.String(50), nullable=False)
    monthly_income = db.Column(db.Numeric(10, 2), nullable=False)
    total_expenses = db.Column(db.Numeric(10, 2))
    savings = db.Column(db.Numeric(10, 2))

    expenses = db.relationship('Expense', backref='budget', cascade='all, delete-orphan')

class Expense(db.Model):
    __tablename__ = 'expenses'
    __table_args__ = {'schema': 'budget_schema'}

    id = db.Column(db.Integer, primary_key=True)
    budget_id = db.Column(
        db.Integer,
        db.ForeignKey('budget_schema.users_budget.id', ondelete='CASCADE'),
    )
    user_id = db.Column(db.Integer, nullable=False)
    day_name = db.Column(db.String(20), nullable=False)
    month_name = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)
    expense_category = db.Column(db.String(100), nullable=False)
    expense_amount = db.Column(db.Numeric(10, 2), nullable=False)"""

# Create schemas if they don't exist
with app.app_context():
    db.create_all()

from functools import wraps
def never_cache(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        # Add headers to disable caching
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return decorated_function

# Application Routes
@app.route('/')
def default():
    if 'user_id' not in session:
        return redirect(url_for('landing_page'))
    return redirect(url_for('dashboard'))

@app.route('/landing_page', methods=['GET'])
def landing_page():
    return render_template('Default.html')

@app.route("/dashboard", methods=["GET", "POST"])
@never_cache
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    # Correct calculation:
    expiry_timestamp = session.get('session_expiry', 0)
    current_time = datetime.now().timestamp()
    remaining_seconds = max(0, int(expiry_timestamp - current_time))  # ← Seconds left

    print(f"Expiry: {expiry_timestamp} | Now: {current_time} | Remaining: {remaining_seconds}s") # Avoid negative values

    if current_time > expiry_timestamp:
        session.clear()
        flash('Session time expired! Please login again', 'error')
        return redirect(url_for('login')) 
    
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))

# 1. Fetch all budgets for the user ordered by newest first
    budget_query = UserBudget.query.filter_by(username=user.name).order_by(UserBudget.id.desc())

    # 2. Try getting the selected month if it exists in session
    selected_month = session.get("selected_month")
    budget = None

    if selected_month:
        budget = budget_query.filter_by(month_name=selected_month).first()

    # 3. Fallback: If no month was selected OR the selected month was deleted,
    # default to the most recent budget in the database and reset session.
    if not budget:
        budget = budget_query.first()  # Already ordered by id.desc()
        if budget:
            session["selected_month"] = budget.month_name
        else:
            session.pop("selected_month", None)  # No budgets exist at all

    expenses = Expense.query.filter_by(budget_id=budget.id).all()
    total_expenses = sum(float(exp.expense_amount) for exp in expenses)
    savings = float(budget.monthly_income) - total_expenses

    budget_result = {
        "month_name": budget.month_name,
        "monthly_income": float(budget.monthly_income),
        "total_expenses": total_expenses,
        "savings": savings,
        "expenses": [{
            "id": exp.id,  # <--- THIS WAS MISSING!
            "category": exp.expense_category,
            "amount": float(exp.expense_amount),
            "dayname": exp.day_name,
            "date": exp.date
        } for exp in expenses]
    }
    
    response = make_response(
               render_template("Index.html", 
               username=user.name,
               budget_result=budget_result, 
               remaining_time=remaining_seconds)
            )
    return response

from flask import render_template, request, redirect, url_for, flash, session, make_response
from datetime import datetime

@app.route("/all-budgets", methods=["GET"])
@never_cache
def all_budgets():
    if 'user_id' not in session:
        flash('Session expired! Please login again', 'error')
        return redirect(url_for('login'))

    username = session.get('username')
    user_id = int(session['user_id']) # Ensure integer type

    # ... [Keep your session expiry check code here] ...

    try:
        all_budgets = UserBudget.query.filter_by(username=username).order_by(UserBudget.id.desc()).all()

        if not all_budgets:
            flash("No budget data found! Please add a month first.", "error")
            return render_template("Allbudgets.html", username=username, budgets=[])

        budget_data = []

        for budget in all_budgets:
            # FIX: Query expenses by budget_id directly. 
            # Avoid filtering by user_id here to prevent DB type casting mismatches.
            expenses = Expense.query.filter_by(budget_id=budget.id).all()

            expense_items = []
            total_expenses = 0.0

            for exp in expenses:
                amount = float(exp.expense_amount)
                expense_items.append({
                    "id": exp.id,
                    "category": exp.expense_category,
                    "expense_category": exp.expense_category,
                    "amount": amount,
                    "expense_amount": amount,
                    "day_name": exp.day_name,
                    "dayname": exp.day_name,
                    "date": exp.date
                })
                total_expenses += amount

            savings = float(budget.monthly_income) - total_expenses

            expense_percentages = []
            if float(budget.monthly_income) > 0:
                expense_percentages = [
                    {
                        "category": item["category"],
                        "percentage": round((item["amount"] / float(budget.monthly_income)) * 100, 2)
                    }
                    for item in expense_items
                ]

            budget_data.append({
                "id": budget.id,
                "month_name": budget.month_name,
                "monthly_income": float(budget.monthly_income),
                "total_expenses": total_expenses,
                "savings": savings,
                "savings_percentage": round((savings / float(budget.monthly_income)) * 100, 2) if float(budget.monthly_income) > 0 else 0,
                "expenses": expense_items,
                "expense_percentages": expense_percentages
            })

        response = make_response(render_template("Allbudgets.html", username=username, budgets=budget_data, now=datetime.now()))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    except Exception as e:
        flash(f"Error retrieving budget data: {str(e)}", "error")
        return render_template("Allbudgets.html", username=username, budgets=[])

"""@app.route("/all-budgets", methods=["GET"])
@never_cache
def all_budgets():
    if 'user_id' not in session:
        flash('Session expired! Please login again', 'error')
        return redirect(url_for('login'))

    username = session.get('username')
    user_id = session['user_id']
    expiry_time = session.get('session_expiry', 0)
    current_time = datetime.now().timestamp()

    if current_time > expiry_time:
        session.clear()
        flash('Session time expired! Please login again', 'error')
        return redirect(url_for('login'))

    try:
        all_budgets = UserBudget.query.filter_by(username=username).order_by(UserBudget.id.desc()).all()

        if not all_budgets:
            flash("No budget data found! Please add a month first.", "error")
            return render_template("Allbudgets.html", username=username, budgets=[])

        budget_data = []

        for budget in all_budgets:
            expenses = Expense.query.filter_by(user_id=user_id, budget_id=budget.id).all()

            expense_items = []
            total_expenses = 0.0

            for exp in expenses:
                amount = float(exp.expense_amount)
                # ADDED: "id": exp.id so template has access to expense primary keys
                expense_items.append({
                    "id": exp.id,
                    "category": exp.expense_category,
                    "amount": amount,
                    "day_name": exp.day_name,
                    "date": exp.date
                })
                total_expenses += amount

            savings = float(budget.monthly_income) - total_expenses

            expense_percentages = []
            if float(budget.monthly_income) > 0:
                expense_percentages = [
                    {
                        "category": item["category"],
                        "percentage": round((item["amount"] / float(budget.monthly_income)) * 100, 2)
                    }
                    for item in expense_items
                ]

            budget_data.append({
                "id": budget.id,
                "month_name": budget.month_name,
                "monthly_income": float(budget.monthly_income),
                "total_expenses": total_expenses,
                "savings": savings,
                "savings_percentage": round((savings / float(budget.monthly_income)) * 100, 2) if float(budget.monthly_income) > 0 else 0,
                "expenses": expense_items,
                "expense_percentages": expense_percentages
            })

        response = make_response(render_template("Allbudgets.html", username=username, budgets=budget_data, now=datetime.now()))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    
    except Exception as e:
        flash(f"Error retrieving budget data: {str(e)}", "error")
        return render_template("Allbudgets.html", username=username, budgets=[])"""

@app.route('/add_month', methods=['POST'])
def add_month():
    if 'user_id' not in session:
        flash('You must login to do this task!','error')
        return redirect(url_for('login'))
    
    if request.method == "POST":
        username = session.get('username')
        user_id = session.get('user_id')
        date = request.form.get("date").strip()
        monthly_income = request.form.get("income").strip()

        if not(date or monthly_income):
            flash('All fields are required!', 'error')
            return redirect(url_for('dashboard'))
        
        if float(monthly_income) <= 0.0:
            flash('Monthly income must be positive!', 'error')
            return redirect(url_for('dashboard'))
    
        month_map = {
            '01': 'January', '02': 'February', '03': 'March', '04': 'April', '05': 'May', '06': 'June',
            '07': 'July', '08': 'August', '09': 'September', '10': 'October', '11': 'November','12': 'December'
        }

        month = str(date[5:7]) 
        month_name = month_map[month]

        try:
            session["selected_month"] = month_name  

            user_budget = UserBudget.query.filter_by(user_id=user_id, username=username, month_name=month_name).first()

            if user_budget:
                user_budget.monthly_income = monthly_income
                db.session.commit() 
                flash('Month & Monthly income updated successfully!','success')
            else:
                new_budget = UserBudget(user_id=user_id, username=username, month_name=month_name, monthly_income=monthly_income)
                db.session.add(new_budget)
                db.session.commit()
                flash('Month & Monthly income added successfully!','success')
                
            return redirect(url_for('dashboard'))

        except ValueError:
            flash("Invalid input! please try again.", 'error')
            return redirect(url_for('dashboard'))  # Redirect on error

from datetime import datetime
from flask import session, flash, redirect, url_for, request

@app.route('/edit_expense', methods=['POST'])
def edit_expense():
    if 'user_id' not in session:
        flash("Please log in to make changes.", 'error')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    expense_id = request.form.get('expense_id')
    raw_category = request.form.get('category', '').strip()
    raw_amount = request.form.get('amount', '').strip()
    target_page = request.form.get('target_page', '').strip() or 'dashboard'

    if not raw_category or not raw_amount:
        flash("Please enter both category and expense amount.", 'error')
        return redirect(url_for(target_page))

    try:
        new_amount = float(raw_amount)
        if new_amount < 0:
            flash("Please enter a valid positive expense amount.", 'error')
            return redirect(url_for(target_page))
    except ValueError:
        flash("Invalid expense amount entered.", 'error')
        return redirect(url_for(target_page))

    try:
        expense = db.session.get(Expense, int(expense_id)) if expense_id else None

        # Fixed Integer type cast for MySQL compatibility
        if expense and int(expense.user_id) == int(user_id):
            if expense.expense_category == raw_category and float(expense.expense_amount) == new_amount:
                flash('No changes were made to the expense.', 'info')
            else:
                expense.expense_category = raw_category
                expense.expense_amount = new_amount
                db.session.commit()

                # Recalculate parent budget totals
                budget = UserBudget.query.get(expense.budget_id)
                if budget:
                    expenses = Expense.query.filter_by(budget_id=budget.id).all()
                    budget.total_expenses = sum(float(exp.expense_amount) for exp in expenses)
                    budget.savings = float(budget.monthly_income) - budget.total_expenses
                    db.session.commit()

                flash('Expense updated successfully!', 'success')
        else:
            flash('Expense record not found.', 'error')

    except Exception as e:
        db.session.rollback()
        flash(f'Failed to update expense: {str(e)}', 'error')

    return redirect(url_for(target_page))


@app.route('/edit_income', methods=['POST'])
def edit_income():
    if 'user_id' not in session:
        flash("Please log in to make changes.", 'error')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    target_page = request.form.get('target_page', '').strip() or 'dashboard'
    month_name = request.form.get('month_name', '').strip()
    raw_income = request.form.get('new_income', '').strip()

    try:
        new_income = float(raw_income)
        if new_income < 0:
            flash("Please enter a valid income amount.", 'error')
            return redirect(url_for(target_page))
    except ValueError:
        flash("Invalid income value entered.", 'error')
        return redirect(url_for(target_page))

    try:
        # Cast user_id to int for strict MySQL query matching
        budget = UserBudget.query.filter_by(user_id=int(user_id), month_name=month_name).first()
        if budget:
            if float(budget.monthly_income) == new_income:
                flash('No changes were made to monthly income.', 'info')
            else:
                budget.monthly_income = new_income
                budget.savings = new_income - float(budget.total_expenses or 0)
                db.session.commit()
                flash('Monthly income updated successfully!', 'success')
        else:
            flash(f'No budget exists for {month_name}. Please add a budget first.', 'error')

    except Exception as e:
        db.session.rollback()
        flash('Failed to update income. Please try again.', 'error')

    return redirect(url_for(target_page))


@app.route('/add_data', methods=['POST'])
def add_data():
    if 'user_id' not in session:
        flash('You must login to do this task!', 'error')
        return redirect(url_for('login'))

    flag = request.form.get('flag', '').strip()
    target_page = 'dashboard' if flag == 'index' else 'all_budgets'

    try:
        date_str = request.form.get('exp_date', '').strip()
        exp_category = request.form.get('exp_category', '').strip()
        exp_amount = request.form.get('exp_amount', '').strip()
        user_id = session.get('user_id')

        if not all([date_str, exp_category, exp_amount]):
            flash('All fields are required!', 'error')
            return redirect(url_for(target_page))

        if not exp_category.replace(" ", "").isalpha():
            flash('Expense category must contain only letters and spaces!', 'error')
            return redirect(url_for(target_page))

        try:
            exp_amount = float(exp_amount)
            if exp_amount <= 0:
                flash('Expense amount must be positive!', 'error')
                return redirect(url_for(target_page))
        except ValueError:
            flash('Expense amount must be a valid number!', 'error')
            return redirect(url_for(target_page))

        try:
            date_obj = datetime.strptime(date_str, "%Y-%m-%d")
            month_name = date_obj.strftime("%B").strip()
            day_name = date_obj.strftime("%A")
        except ValueError:
            flash('Invalid date format! Please use YYYY-MM-DD.', 'error')
            return redirect(url_for(target_page))

        target_month_name = request.form.get('month_name', '').strip()

        if target_month_name and target_month_name != month_name:
            flash(f"Date error: You selected a date in {month_name}, but you are adding an expense inside the {target_month_name} block!", "error")
            return redirect(url_for(target_page))

        # Query budget with int user_id cast
        budget = UserBudget.query.filter_by(user_id=int(user_id), month_name=month_name).first()

        if not budget:
            msg = (
                f"Please create a budget for {month_name} using the 'Budget Controls' section on the left."
                if flag == 'index'
                else f"No budget exists for {month_name}. Please add a budget for {month_name} first."
            )
            flash(msg, "error")
            return redirect(url_for(target_page))

        new_expense = Expense(
            user_id=int(user_id),
            budget_id=budget.id,
            day_name=day_name,
            month_name=month_name,
            date=date_obj.date(),  # Pass Python date object to db.Date column
            expense_category=exp_category,
            expense_amount=exp_amount
        )
        db.session.add(new_expense)
        db.session.commit()

        # Recalculate Totals
        expenses = Expense.query.filter_by(budget_id=budget.id).all()
        total_expenses = sum(float(exp.expense_amount) for exp in expenses)
        savings = float(budget.monthly_income) - total_expenses

        budget.total_expenses = total_expenses
        budget.savings = savings
        db.session.commit()

        session['selected_month'] = month_name
        flash("Expense added successfully!", 'success')
        return redirect(url_for(target_page))

    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {str(e)}", 'error')
        return redirect(url_for(target_page))


@app.route('/delete_expense', methods=['POST'])
def delete_expense():
    if 'user_id' not in session:
        flash("Please log in first.", 'error')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    expense_id = request.form.get('expense_id')
    target_page = request.form.get('target_page', '').strip() or 'dashboard'

    if not expense_id:
        flash("Missing expense identifier.", 'error')
        return redirect(url_for(target_page))

    try:
        expense = db.session.get(Expense, int(expense_id))
        
        if expense:
            owner_id = getattr(expense, 'user_id', None) or (expense.budget.user_id if expense.budget else None)
            
            # Integer cast comparison to fix MySQL type mismatch
            if owner_id is not None and int(owner_id) == int(user_id):
                budget_id = expense.budget_id
                
                db.session.delete(expense)
                db.session.commit()

                # Recalculate parent budget totals after deletion
                budget = UserBudget.query.get(budget_id)
                if budget:
                    expenses = Expense.query.filter_by(budget_id=budget.id).all()
                    budget.total_expenses = sum(float(exp.expense_amount) for exp in expenses)
                    budget.savings = float(budget.monthly_income) - budget.total_expenses
                    db.session.commit()

                flash('Expense item deleted successfully!', 'success')
            else:
                flash('Permission denied.', 'error')
        else:
            flash('Expense record not found.', 'error')

    except Exception as e:
        db.session.rollback()
        flash('Failed to remove expense.', 'error')

    return redirect(url_for(target_page))

"""@app.route('/edit_income', methods=['POST'])
def edit_income():
    if 'user_id' not in session:
        flash("Please log in to make changes.", 'error')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    target_page = request.form.get('target_page', 'dashboard').strip()
    month_name = request.form.get('month_name')
    raw_income = request.form.get('new_income').strip()

    if not raw_income or float(raw_income) < 0:
        flash("Please enter a valid income amount.", 'error')
        return redirect(url_for(target_page))

    try:
        new_income = float(raw_income)
    except ValueError:
        flash("Invalid income value entered.", 'error')
        return redirect(url_for(target_page))

    try:
        budget = UserBudget.query.filter_by(user_id=user_id, month_name=month_name).first()
        if budget:
            if budget.monthly_income == new_income:
                flash('No changes were made to monthly income.', 'info')
            else:
                budget.monthly_income = new_income
                db.session.commit()
                flash('Monthly income updated successfully!', 'success')
        else:
            flash('Budget record not found.', 'error')

    except Exception:
        db.session.rollback()
        flash('Failed to update income. Please try again.', 'error')

    return redirect(url_for(target_page))

@app.route('/edit_expense', methods=['POST'])
def edit_expense():
    if 'user_id' not in session:
        flash("Please log in to make changes.", 'error')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    expense_id = request.form.get('expense_id')
    raw_category = request.form.get('category').strip()
    raw_amount = request.form.get('amount').strip()
    target_page = request.form.get('target_page', 'dashboard').strip()

    if not raw_category or not raw_amount:
        flash("Please enter both category and expense amount.", 'error')
        return redirect(url_for(target_page))

    if not raw_amount or float(raw_amount) < 0:
        flash("Please enter a valid expense amount.", 'error')
        return redirect(url_for(target_page))

    try:
        new_amount = float(raw_amount)
    except ValueError:
        flash("Invalid expense amount entered.", 'error')
        return redirect(url_for(target_page))

    new_category = raw_category.strip()

    try:
        expense = db.session.get(Expense, int(expense_id)) if expense_id else None

        if expense and str(expense.user_id) == str(user_id):            
            if expense.expense_category == new_category and float(expense.expense_amount) == new_amount:
                flash('No changes were made to the expense.', 'info')
            else:
                expense.expense_category = new_category
                expense.expense_amount = new_amount
                db.session.commit()
                flash('Expense updated successfully!', 'success')
        else:
            flash('Expense record not found.', 'error')

    except Exception as e:
        db.session.rollback()
        flash('Failed to update expense. Please try again.', 'error')

    # UPDATED: Redirects back to all_budgets page
    return redirect(url_for(target_page))
"""

# Weekly Report Email Sending Route
import os
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import jsonify

import os
import smtplib
from datetime import datetime
from collections import defaultdict
from urllib.parse import quote
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_weekly_budget_reports():
    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASS')
    app_url = "https://budgetwisely.pythonanywhere.com"

    if not sender_email or not sender_password:
        print("❌ Email credentials missing in environment variables")
        return False

    try:
        users = User.query.all()
        if not users:
            print("No users found in database.")
            return False

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            emails_sent = 0

            for user in users:
                try:
                    # 1. Fetch current month data
                    current_month_name = datetime.now().strftime("%B")  # e.g., "July"
                    budget = UserBudget.query.filter_by(
                        user_id=user.user_id, 
                        month_name=current_month_name
                    ).first()

                    expenses = Expense.query.filter_by(
                        user_id=user.user_id,
                        month_name=current_month_name
                    ).order_by(Expense.date.desc()).all()

                    # Skip if no budget setup and no expenses logged
                    if not budget and not expenses:
                        print(f"⏩ Skipped {user.email}: No records for {current_month_name}.")
                        continue

                    # 2. Financial Calculations
                    monthly_income = float(budget.monthly_income) if budget else 0.00
                    total_expenses = sum(float(e.expense_amount) for e in expenses)
                    net_savings = monthly_income - total_expenses
                    
                    savings_percent = round((net_savings / monthly_income) * 100, 1) if monthly_income > 0 else 0
                    expense_percent = round((total_expenses / monthly_income) * 100, 1) if monthly_income > 0 else 0
                    savings_color = "#27ae60" if net_savings >= 0 else "#e74c3c"

                    # 3. Aggregate Expenses by Category for Chart
                    cat_totals = defaultdict(float)
                    for exp in expenses:
                        cat_totals[exp.expense_category] += float(exp.expense_amount)

                    # Build QuickChart API Donut Chart URL
                    chart_html = ""
                    if cat_totals:
                        cat_labels = list(cat_totals.keys())[:5]
                        cat_values = [round(cat_totals[k], 2) for k in cat_labels]
                        
                        chart_config = f"""{{
                            type: 'doughnut',
                            data: {{
                                labels: {cat_labels},
                                datasets: [{{
                                    data: {cat_values},
                                    backgroundColor: ['#27ae60', '#3498db', '#e74c3c', '#f1c40f', '#9b59b6']
                                }}]
                            }},
                            options: {{
                                plugins: {{
                                    legend: {{ position: 'bottom', labels: {{ color: '#94a3b8', font: {{ size: 10 }} }} }},
                                    title: {{ display: true, text: 'Expense Breakdown by Category', color: '#ffffff', font: {{ size: 12 }} }}
                                }}
                            }}
                        }}"""
                        
                        encoded_config = quote(chart_config.replace('\n', '').replace(' ', ''))
                        chart_url = f"https://quickchart.io/chart?c={encoded_config}&w=450&h=220&bkg=transparent"
                        
                        chart_html = f"""
                        <div style="text-align: center; margin: 20px 0; background-color: #0f172a; padding: 15px; border-radius: 12px; border: 1px solid #334155;">
                            <img src="{chart_url}" alt="Expense Breakdown Chart" style="max-width: 100%; height: auto; border: 0;" />
                        </div>
                        """

                    # 4. Generate Expense Table Rows
                    if expenses:
                        expense_rows = ""
                        for exp in expenses[:6]:
                            expense_rows += f"""
                            <tr>
                                <td style="padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 13px; color: #f8fafc;">{exp.expense_category}</td>
                                <td style="padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 13px; color: #94a3b8;">{exp.date}</td>
                                <td style="padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 13px; color: #f87171; font-weight: bold; text-align: right;">₹{float(exp.expense_amount):,.2f}</td>
                            </tr>
                            """
                        
                        expense_table_html = f"""
                        <h4 style="color: #4ade80; font-size: 12px; font-weight: 800; letter-spacing: 1px; margin: 24px 0 10px 0; text-transform: uppercase;">
                            📋 Recent Transactions ({len(expenses)})
                        </h4>
                        <table style="width: 100%; border-collapse: collapse; background-color: #0f172a; border-radius: 12px; overflow: hidden; border: 1px solid #334155;" cellpadding="0" cellspacing="0">
                            <thead>
                                <tr style="background-color: #1e293b; text-align: left;">
                                    <th style="padding: 10px 12px; font-size: 11px; color: #94a3b8; text-transform: uppercase;">Category</th>
                                    <th style="padding: 10px 12px; font-size: 11px; color: #94a3b8; text-transform: uppercase;">Date</th>
                                    <th style="padding: 10px 12px; font-size: 11px; color: #94a3b8; text-transform: uppercase; text-align: right;">Amount</th>
                                </tr>
                            </thead>
                            <tbody>
                                {expense_rows}
                            </tbody>
                        </table>
                        """
                    else:
                        expense_table_html = """
                        <div style="text-align: center; padding: 18px; background-color: #0f172a; border-radius: 12px; margin-top: 15px; border: 1px dashed #334155;">
                            <p style="margin: 0; font-size: 13px; color: #94a3b8;">🎉 No expenses logged for this month yet!</p>
                        </div>
                        """

                    # 5. Build Standardized HTML Email Layout
                    html_body = f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    </head>
                    <body style="margin: 0; padding: 0; background-color: #0b1120; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
                        
                        <!-- Outer Outer Table Wrapper to force Top & Bottom Margins on Mobile & Web Gmail -->
                        <table style="width: 100%; background-color: #0b1120; margin: 0; padding: 40px 10px;" cellpadding="0" cellspacing="0" border="0">
                            <tr>
                                <td align="center">
                                    
                                    <!-- Central Email Card -->
                                    <table style="max-width: 540px; width: 100%; background-color: #1e293b; border-radius: 16px; border: 1px solid #334155; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);" cellpadding="0" cellspacing="0" border="0">
                                        <tr>
                                            <td style="padding: 32px 24px;">
                                                
                                                <!-- Header -->
                                                <div style="text-align: center; margin-bottom: 24px;">
                                                    <h1 style="margin: 0; font-size: 24px; color: #ffffff; font-weight: 800; letter-spacing: -0.5px;">💰 Budget Wisely</h1>
                                                    <p style="margin: 6px 0 0 0; font-size: 13px; color: #94a3b8;">Weekly Financial Digest • {current_month_name}</p>
                                                </div>

                                                <p style="font-size: 14px; color: #e2e8f0; margin-bottom: 20px; line-height: 1.5;">
                                                    Hi <strong>{user.name}</strong>, here is your real-time financial report for {current_month_name}:
                                                </p>

                                                <!-- Metric Cards -->
                                                <table style="width: 100%; border-collapse: separate; border-spacing: 6px; margin-bottom: 20px;" cellpadding="0" cellspacing="0">
                                                    <tr>
                                                        <td style="width: 33%; background-color: #0f172a; padding: 12px 8px; border-radius: 10px; border: 1px solid #334155; text-align: center;">
                                                            <div style="color: #94a3b8; font-size: 10px; font-weight: 700; margin-bottom: 4px;">INCOME</div>
                                                            <div style="font-size: 14px; font-weight: bold; color: #4ade80;">₹{monthly_income:,.2f}</div>
                                                        </td>
                                                        <td style="width: 33%; background-color: #0f172a; padding: 12px 8px; border-radius: 10px; border: 1px solid #334155; text-align: center;">
                                                            <div style="color: #94a3b8; font-size: 10px; font-weight: 700; margin-bottom: 4px;">EXPENSES</div>
                                                            <div style="font-size: 14px; font-weight: bold; color: #f87171;">₹{total_expenses:,.2f}</div>
                                                            <div style="font-size: 9px; color: #94a3b8; margin-top: 2px;">({expense_percent}%)</div>
                                                        </td>
                                                        <td style="width: 33%; background-color: #0f172a; padding: 12px 8px; border-radius: 10px; border: 1px solid #334155; text-align: center;">
                                                            <div style="color: #94a3b8; font-size: 10px; font-weight: 700; margin-bottom: 4px;">SAVINGS</div>
                                                            <div style="font-size: 14px; font-weight: bold; color: {savings_color};">₹{net_savings:,.2f}</div>
                                                            <div style="font-size: 9px; color: #94a3b8; margin-top: 2px;">({savings_percent}%)</div>
                                                        </td>
                                                    </tr>
                                                </table>

                                                <!-- Progress Bar -->
                                                <div style="margin-bottom: 20px; background-color: #0f172a; padding: 12px; border-radius: 10px; border: 1px solid #334155;">
                                                    <div style="display: flex; justify-content: space-between; font-size: 11px; color: #94a3b8; margin-bottom: 6px;">
                                                        <span>Budget Spent</span>
                                                        <span style="font-weight: bold; color: #ffffff;">{expense_percent}%</span>
                                                    </div>
                                                    <div style="background-color: #334155; border-radius: 6px; height: 8px; overflow: hidden;">
                                                        <div style="background-color: {'#f87171' if expense_percent > 90 else '#4ade80'}; width: {min(expense_percent, 100)}%; height: 8px; border-radius: 6px;"></div>
                                                    </div>
                                                </div>

                                                <!-- Category Breakdown Chart -->
                                                {chart_html}

                                                <!-- Expense Table -->
                                                {expense_table_html}

                                                <!-- Button CTA -->
                                                <div style="text-align: center; margin-top: 28px;">
                                                    <a href="{app_url}" style="background-color: #22c55e; color: #ffffff; padding: 12px 28px; text-decoration: none; border-radius: 10px; font-size: 13px; font-weight: bold; display: inline-block; box-shadow: 0 4px 12px rgba(34, 197, 94, 0.3);">
                                                        Control Your Budget
                                                    </a>
                                                </div>

                                                <!-- Footer -->
                                                <div style="height: 1px; background-color: #334155; margin: 28px 0 16px 0;"></div>
                                                <p style="font-size: 11px; color: #ffffff; text-align: center; margin: 0;">
                                                    Budget Wisely • Smart Financial Tracking
                                                </p>

                                            </td>
                                        </tr>
                                    </table>

                                </td>
                            </tr>
                        </table>

                    </body>
                    </html>
                    """

                    # 6. Send
                    msg = MIMEMultipart("alternative")
                    msg['From'] = sender_email
                    msg['To'] = user.email
                    msg['Subject'] = f"📊 Budget Summary for {current_month_name} - Budget Wisely"
                    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

                    server.send_message(msg)
                    emails_sent += 1
                    print(f"✅ Email report delivered to {user.email}")

                except Exception as user_err:
                    print(f"❌ Error sending to user ID {user.user_id}: {str(user_err)}")
                    continue

            return emails_sent > 0

    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        return False
    
# 🧪 Test Route: Trigger weekly budget digest manually
@app.route('/api/send-weekly-budget-email')
def trigger_weekly_budget_email():
    print("🚀 Manual trigger: Sending weekly budget reports...")
    try:
        success = send_weekly_budget_reports()
        if success:
            return jsonify({"status": "success", "message": "Successfully sent weekly budget emails!"}), 200
        else:
            return jsonify({"status": "info", "message": "No emails sent. Check server logs."}), 200
    except Exception as err:
        return jsonify({"status": "error", "message": f"Execution error: {str(err)}"}), 500

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()

        # Validate inputs
        if password != confirm_password:
            flash("Passwords don't match!", "error")
        elif password[0].isdigit():
            flash("Password must start with a letter!", "error")
        elif len(password) < 6:
            flash("Password too short (min 6 chars)!", "error")
        else:
            try:
                validate_email(email)
                
                if User.query.filter_by(email=email).first():
                    flash("Email already exists!", 'error')
                else:
                    new_user = User(
                        name=name,
                        email=email,
                        password=generate_password_hash(password)
                    )
                    db.session.add(new_user)
                    db.session.commit()
                    flash("Registration successful! Please login.", 'success')
                    return redirect(url_for('login'))
            
            except EmailNotValidError as e:
                flash(str(e), "error")
            except Exception as e:
                db.session.rollback()
                flash(f"Database error: {str(e)}", "error")
        
        return redirect(url_for('signup'))

    return render_template('Signup.html')

@app.route('/login', methods=['GET', 'POST'])
@never_cache
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        try:
            user = User.query.filter_by(email=email).first()

            if user and check_password_hash(user.password, password):
                session['user_id'] = user.user_id
                session['username'] = user.name
                session.permanent = True  # Enable session expiration

                expiry_time = datetime.now() + timedelta(minutes=30)  # Set session expiry time
                session['session_expiry'] = expiry_time.timestamp()  # Store expiry time as timestamp
                
                flash("Login successful!", 'success')
                return redirect(url_for("dashboard"))
            
            flash("Invalid credentials!", 'error')
        except Exception as e:
            flash(f"Database error: {str(e)}", "error")
        
        return redirect(url_for("login"))

    return render_template('Login.html')

# Forgot password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').strip()  # Ensure no extra spaces
        user = User.query.filter_by(email=email).first()

        if user:
            if send_otp(email):
                flash("OTP sent successfully!", "success")
                return redirect(url_for('verify_otp'))
            else:
                flash("Failed to send OTP. Try again later.", "error")
        else:
            flash("No account found with this email!", "error")
    #session.pop('email', None)
    return render_template('Forgotpass.html')

@app.route('/resend_otp')
def resend_otp():
    email = session.get('email')

    if not email:
        flash("Session expired! Please request for new otp.", "error")
        return redirect(url_for('forgot_password'))

    sent_otp = send_otp(email)

    if not sent_otp:
        flash("Failed to resend OTP. Please try again.", "error")
        return redirect(url_for('verify_otp'))

    flash("New OTP sent successfully!", "success")
    return redirect(url_for('verify_otp'))
    
# Send OTP via Email
def send_otp(email):
    print("Sender:", os.getenv("SENDER_EMAIL"))
    otp = random.randint(100000, 999999)
    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASS')

    if not sender_email or not sender_password:
        print("Error: Email credentials not set")
        return False
    
    subject = "Password Reset OTP"
    body = f"Your OTP for password reset is: {otp}"
    message = f"Subject: {subject}\n\n{body}"

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message)
        print(email)
        print(otp)
        session['email'] = email
        session['sent_otp'] = otp
        session['otp_expiry'] = (datetime.now() + timedelta(minutes=5)).timestamp()
        return True
    return False

# Verify OTP Route
@app.route('/verify_otp', methods=['GET', 'POST'])
@never_cache
def verify_otp():
    # Prevent direct access if OTP was not sent
    email = session.get('email')  # Retrieve email from session
    sent_otp = session.get('sent_otp')  # Retrieve stored OTP
    otp_expiry = session.get('otp_expiry')  # Retrieve OTP expiry time

    if not email:
        session.clear()
        flash("Session expired! Please request for new otp.", "error")
        return redirect(url_for('forgot_password'))

    if not sent_otp:
        session.clear()
        flash("OTP expired! Please request for new otp.", "error")
        return redirect(url_for('forgot_password'))

    if not otp_expiry:
        session.clear()
        flash("OTP expiry not found! Please request for new otp.", "error")
        return redirect(url_for('forgot_password'))
        
    # Check if OTP has expired
    if datetime.now().timestamp() > otp_expiry:
        session.pop('sent_otp', None)  # Remove expired OTP
        session.pop('otp_expiry', None)
        session.pop('email', None)
        session.clear()
        flash("OTP has expired! Please request a new one.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()  # Ensure OTP is stripped of spaces

        # Validate OTP
        if str(sent_otp) == entered_otp:
            # OTP is valid; clean up session
            session.pop('sent_otp', None)
            session.pop('otp_expiry', None)
            session.pop('email', None)

            session['verified_email'] = email  # Store verified email

            flash("OTP verified successfully! Please reset your password.", "success")
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid OTP! Please try again.", "error")
            return redirect(url_for('verify_otp'))

    return render_template('VerifyOTP.html')

# Reset Password using OTP
@app.route('/reset_password', methods=['GET', 'POST'])
@never_cache
def reset_password():
    email = session.get('verified_email')  # Retrieve email using the correct key
    # Prevent unauthorized access
    if not email:
        session.clear()
        flash('OTP expired! Please verify with OTP first.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        cpassword = request.form.get('cpassword', '').strip()

        # Validate passwords
        if not password or not cpassword:
            flash('Password fields cannot be empty!', 'error')
        elif password[0].isdigit():
            flash("Password must start with a letter!", "error")
        elif len(password) < 6:
            flash("Password too short (min 6 chars)!", "error")
        elif password != cpassword:
            flash('Passwords do not match! Please try again.', 'error')
        else:
            try:
                # Update user password
                user = User.query.filter_by(email=email).first()
                if user:
                    user.password = generate_password_hash(password)  # Hash password
                    db.session.commit()

                    # Clean up session after successful reset
                    session.pop('verified_email', None)  # Use 'email' consistently
                    session.clear()
                    flash("Password reset successful! Please log in.", "success")
                    return redirect(url_for('login'))
                else:
                    session.clear()
                    flash("User not found! Please try again.", "error")
                return render_template('Resetpass.html') # added return to prevent the code from continuing.
            except Exception as e:
                db.session.rollback()
                session.clear()
                flash("We are unable to process your request right now. Please try again later.", "error")
                return redirect(url_for('forgot_password'))  # redirect user back to the password reset page.
    return render_template('Resetpass.html')

#Change password for logged in user
@app.route('/change_password', methods=['GET', 'POST'])
@never_cache
def change_pass():
    if 'user_id' not in session:
        flash("Session expired! Please login again.", 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        password = request.form.get('password', '').strip()
        cpassword = request.form.get('cpassword', '').strip()

        # Validate passwords
        if not password or not cpassword:
            flash('Password fields cannot be empty!', 'error')
        elif password[0].isdigit():
            flash("Password must start with a letter!", "error")
        elif len(password) < 6:
            flash("Password too short (min 6 chars)!", "error")
        elif password != cpassword:
            flash('Passwords do not match! Please try again.', 'error')
        else:
            try:
                print("DEBUG: user_id =", user_id)
                user = User.query.get(user_id)
                print("DEBUG: user =", user)

                if not user:
                    flash("User not found! Please try again.", "error")
                    return render_template('Changepass.html')

                user.password = generate_password_hash(password)
                db.session.commit()
                flash("Password changed successfully!", "success")
                return redirect(url_for('dashboard'))

            except Exception as e:
                db.session.rollback()
                print("Exception in change_pass:", e)
                flash("We are unable to process your request right now. Please try again later.", "error")

    return render_template('Changepass.html')
    
@app.route('/about_us')
def about_us():
    return render_template('Aboutus.html')

@app.route('/services')
def services():
    return render_template('Services.html')

@app.route('/contact_us', methods=['GET', 'POST'])
def contact_us():
    if request.method == 'POST':
        name = request.form.get('name').strip()
        number = request.form.get('number').strip()
        email = request.form.get('email').strip()
        message = request.form.get('message').strip()

        if not name or not number or not email or not message:
            flash("All fields are required!", 'error')
            return redirect(url_for('contact_us'))
        else:
            flash(f"Dear {name}, we have received your message! we will get back to you shortly.", 'success')
            return redirect(url_for('contact_us'))

    return render_template('Contact.html')

@app.route('/logout')
def logout():
    session.clear()  # Clears all session keys at once
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

@app.before_request
def check_db_connection():
    try:
        db.session.execute(db.text('SELECT 1'))
    except Exception as e:
        db.session.rollback()
        flash('Database connection error!', 'error')
        return render_template('error.html', error=str(e))

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == '__main__':
    app.run(debug=True)
