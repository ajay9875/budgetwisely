import os
import random
import smtplib
from calendar import month_name
from datetime import datetime, timedelta
from functools import wraps
from flask_migrate import Migrate  # 👈 Add this at the top

from dotenv import load_dotenv
from email_validator import EmailNotValidError, validate_email
from flask import (Flask, flash, make_response, redirect, render_template, request, session, url_for)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash
from dateutil.relativedelta import relativedelta

# Handle PyMySQL binding safely if driver is present
try:
    import pymysql
    pymysql.install_as_MySQLdb()
except ImportError:
    pass

load_dotenv()

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY')
app.config['SESSION_PERMANENT'] = False

# Configure SQLAlchemy Engine
db_uri = os.getenv('DATABASE_URI', '')
# Auto-fix legacy postgres:// scheme to postgresql:// if present
if db_uri.startswith("postgres://"):
    db_uri = db_uri.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'max_overflow': 20,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
    'pool_timeout': 30
}

db = SQLAlchemy(app)

migrate = Migrate(app, db)         # 👈 Add this right after db initialization

# Database Models
class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    vault_pin = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Add this new model at the bottom of your models:
class VaultItem(db.Model):
    __tablename__ = 'vault_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    secret_text = db.Column(db.Text, nullable=False) # Can hold huge amounts of text
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow) # 👈 ADD THIS

class UserBudget(db.Model):
    __tablename__ = 'users_budget'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    month_name = db.Column(db.String(50), nullable=False)
    monthly_income = db.Column(db.Numeric(10, 2), nullable=False)
    total_expenses = db.Column(db.Numeric(10, 2), default=0.0)
    savings = db.Column(db.Numeric(10, 2), default=0.0)

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

with app.app_context():
    db.create_all()

# At the top:
from datetime import datetime, timedelta, timezone
# Ensure IST is defined at the top of your app.py
from zoneinfo import ZoneInfo
IST = ZoneInfo("Asia/Kolkata")

# Add this function right above your routes (e.g., right after the `never_cache` function):
def to_ist(utc_dt):
    if not utc_dt: 
        return None
    # Convert UTC to IST (UTC + 5:30)
    return utc_dt.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=5, minutes=30)))

def never_cache(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return decorated_function

@app.context_processor
def inject_session_status():
    """Expose a real 'is_logged_in' flag to all templates."""
    expiry_ts = session.get('session_expiry', 0)
    now_ts = datetime.now().timestamp()
    user_id = session.get('user_id')

    # Logged in only if user_id exists AND session hasn't expired
    is_logged_in = bool(user_id) and (now_ts <= expiry_ts)

    return dict(is_logged_in=is_logged_in)

@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='icon/favicon.png'))

import os
import pdfkit

# 👇 Safely configure pdfkit (prevents app crash if not installed)

try:
    if os.name == 'nt':
        path_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
        if not os.path.exists(path_wkhtmltopdf):
            path_wkhtmltopdf = r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe'
        config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
    else:
        # 👇 THIS points to the file you just downloaded 👇
        path_wkhtmltopdf = os.path.expanduser('~/wkhtmltopdf/usr/local/bin/wkhtmltopdf')
        
        if os.path.exists(path_wkhtmltopdf):
            config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
        else:
            config = pdfkit.configuration(wkhtmltopdf='/usr/bin/wkhtmltopdf') # Fallback
except Exception as e:
    print(f"⚠️ Warning: wkhtmltopdf not found. PDF export will not work. Error: {e}")
    config = None

# PDF Options (Single, clean definition)
pdf_options = {
    'page-size': 'A4',
    'margin-top': '15mm',
    'margin-right': '15mm',
    'margin-bottom': '15mm',
    'margin-left': '15mm',
    'encoding': "UTF-8",
    'enable-local-file-access': None, # Crucial for CSS/Fonts to load
    'print-media-type': None,
}

# =======================================
# Download pdf route for Dashboard
# =======================================
@app.route("/download_dashboard_pdf")
def download_dashboard_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))

        # 👇 ADD THIS SAFETY CHECK 👇
    if not config or not config.wkhtmltopdf:
        flash("PDF generation is not configured on this server. Please contact support.", "error")
        return redirect(url_for('dashboard'))
    # 👆 END OF SAFETY CHECK 👆
    
    user_id = int(session['user_id'])
    username = session.get('username', 'user')
    cleaned_username = username.capitalize()
    
    # 1. Fetch EXACTLY like the dashboard route
    budget_query = UserBudget.query.filter_by(user_id=user_id).order_by(UserBudget.id.desc())
    selected_month = session.get("selected_month")
    budget = None
    if selected_month:
        budget = budget_query.filter(func.lower(func.trim(UserBudget.month_name)) == selected_month.strip().lower()).first()
    if not budget:
        budget = budget_query.first()
        
    if not budget:
        flash("No data to export.", "error")
        return redirect(url_for('dashboard'))

    # 2. Fetch Expenses
    expenses = Expense.query.filter_by(budget_id=budget.id).order_by(Expense.date.desc(), Expense.id.desc()).all()
    total_expenses = sum(float(exp.expense_amount) for exp in expenses)
    savings = float(budget.monthly_income) - total_expenses
    
    category_totals = {}
    for exp in expenses:
        cat = exp.expense_category
        amt = float(exp.expense_amount)
        category_totals[cat] = category_totals.get(cat, 0) + amt

    # 3. Build the dict
    budget_result = {
        "month_name": budget.month_name,
        "monthly_income": float(budget.monthly_income),
        "total_expenses": total_expenses,
        "savings": savings,
        "category_totals": category_totals,
        "expenses": [{
            "id": exp.id, "category": exp.expense_category, "amount": float(exp.expense_amount),
            "dayname": exp.day_name, "date": exp.date
        } for exp in expenses]
    }

    # 4. Generate QuickChart Images
    from urllib.parse import quote
    
    # -- Chart 1: Budget Breakdown (Bar Chart) --
    bar_config = f"""{{
        type: 'bar',
        data: {{
            labels: ['Income', 'Expenses', 'Savings'],
            datasets: [{{
                label: 'Amount (₹)',
                data: [{budget_result['monthly_income']}, {budget_result['total_expenses']}, {budget_result['savings']}],
                backgroundColor: ['#4F46E5', '#EF4444', '#10B981'],
                borderRadius: 4,
                barPercentage: 0.5
            }}]
        }},
        options: {{
            plugins: {{ legend: {{ display: false }} }},
            scales: {{ 
                y: {{ beginAtZero: true }},
                x: {{ grid: {{ display: false }} }}
            }}
        }}
    }}"""
    bar_url = f"https://quickchart.io/chart?c={quote(bar_config.replace('\n', '').replace(' ', ''))}&w=500&h=250&bkg=white"

    # -- Chart 2: Income Allocation (Doughnut Chart) --
    alloc_config = f"""{{
        type: 'doughnut',
        data: {{
            labels: ['Expenses', 'Savings'],
            datasets: [{{
                data: [{budget_result['total_expenses']}, {max(0, budget_result['savings'])}],
                backgroundColor: ['#f43f5e', '#10b981']
            }}]
        }},
        options: {{
            plugins: {{ legend: {{ position: 'bottom' }} }}
        }}
    }}"""
    alloc_url = f"https://quickchart.io/chart?c={quote(alloc_config.replace('\n', '').replace(' ', ''))}&w=400&h=250&bkg=white"

    # -- Chart 3: Expense Categories (Doughnut Chart) --
    cat_labels = list(category_totals.keys())
    cat_values = list(category_totals.values())
    
    if cat_labels:
        pie_config = f"""{{
            type: 'doughnut',
            data: {{
                labels: {cat_labels},
                datasets: [{{
                    data: {cat_values},
                    backgroundColor: ['#818cf8', '#f472b6', '#fbbf24', '#34d399', '#a78bfa', '#22d3ee']
                }}]
            }},
            options: {{
                plugins: {{ legend: {{ position: 'bottom' }} }}
            }}
        }}"""
        pie_url = f"https://quickchart.io/chart?c={quote(pie_config.replace('\n', '').replace(' ', ''))}&w=400&h=250&bkg=white"
    else:
        pie_url = None

    # 5. Render template
    logo_url = url_for('static', filename='icon/favicon.png', _external=True)

    html = render_template(
        'pdf_dashboard.html', 
        budget_result=budget_result, 
        username=cleaned_username,
        now=datetime.now(IST),
        bar_url=bar_url,
        alloc_url=alloc_url,  # 👈 Add this
        pie_url=pie_url,
        logo_url=logo_url
    )
        
    try:
        pdf = pdfkit.from_string(html, False, options=pdf_options, configuration=config)
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        
        # e.g., budget_wisely_february_2027_monthly_report_13_Nov_2026_03-42AM
        safe_month_name = budget.month_name.replace(' ', '_').lower()
        timestamp = datetime.now(IST).strftime('%d_%b_%Y_%I-%M%p')
        filename = f"budget_wisely_{safe_month_name}_monthly_report_{timestamp}.pdf"
        
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    except Exception as e:
        flash(f"PDF generation failed: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route("/download_all_budgets_pdf")
def download_all_budgets_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = int(session['user_id'])
    username = session.get('username', 'user')
    cleaned_username = username.capitalize()
    
    scope = request.args.get('scope', 'lifetime') 
    target_year = request.args.get('year')
    target_month = request.args.get('month')

    MONTH_ORDER = {
        'January': 1, 'February': 2, 'March': 3, 'April': 4,
        'May': 5, 'June': 6, 'July': 7, 'August': 8,
        'September': 9, 'October': 10, 'November': 11, 'December': 12
    }

    all_user_budgets = UserBudget.query.filter_by(user_id=user_id).order_by(UserBudget.id.desc()).all()
    if not all_user_budgets:
        flash("No data to export.", "error")
        return redirect(url_for('all_budgets'))

    # 1. Build the exact same structure as the website
    groups = {}
    uncategorized = []

    for budget in all_user_budgets:
        expenses = Expense.query.filter_by(budget_id=budget.id).order_by(Expense.date.desc()).all()
        expense_items = []
        total_expenses = 0.0
        
        category_totals = {}
        for exp in expenses:
            amount = float(exp.expense_amount)
            expense_items.append({
                "category": exp.expense_category, "amount": amount,
                "dayname": exp.day_name, "date": exp.date
            })
            total_expenses += amount
            category_totals[exp.expense_category] = category_totals.get(exp.expense_category, 0) + amount

        savings = float(budget.monthly_income) - total_expenses
        raw_month = (budget.month_name or "").strip()
        parts = raw_month.split()
        month_word = parts[0] if parts else ""
        year_val = None
        for token in parts[1:]:
            if token.isdigit():
                year_val = int(token)
                break

        record = {
            "month_name": raw_month, "month_word": month_word, "month_num": MONTH_ORDER.get(month_word, 0),
            "year": year_val, "monthly_income": float(budget.monthly_income),
            "total_expenses": total_expenses, "savings": savings,
            "category_totals": category_totals, "expenses": expense_items
        }

        if year_val is None:
            uncategorized.append(record)
        else:
            groups.setdefault(year_val, []).append(record)

    budgets_by_year = []
    for year in sorted(groups.keys(), reverse=True):
        year_budgets = sorted(groups[year], key=lambda b: (b["month_num"], b["month_name"]), reverse=True)
        total_income = sum(b["monthly_income"] for b in year_budgets)
        total_exp = sum(b["total_expenses"] for b in year_budgets)
        
        budgets_by_year.append({
            "label": str(year), "year": year, "is_uncategorized": False, "budgets": year_budgets,
            "total_income": total_income, "total_expenses": total_exp, "total_savings": total_income - total_exp
        })

    if uncategorized:
        uncategorized.sort(key=lambda b: (b["month_num"], b["month_name"]), reverse=True)
        total_income = sum(b["monthly_income"] for b in uncategorized)
        total_exp = sum(b["total_expenses"] for b in uncategorized)
        budgets_by_year.append({
            "label": "Uncategorized", "year": None, "is_uncategorized": True, "budgets": uncategorized,
            "total_income": total_income, "total_expenses": total_exp, "total_savings": total_income - total_exp
        })

    lifetime_income = sum(g['total_income'] for g in budgets_by_year)
    lifetime_expenses = sum(g['total_expenses'] for g in budgets_by_year)
    lifetime_savings = lifetime_income - lifetime_expenses

    # 2. Filter based on scope
    filtered_groups = []
    for group in budgets_by_year:
        if scope == 'lifetime':
            filtered_groups.append(group)
        elif scope == 'yearly' and str(group['label']) == str(target_year):
            filtered_groups.append(group)
        elif scope == 'monthly':
            # Only keep the specific month
            matching_budgets = [b for b in group['budgets'] if b['month_name'].lower() == target_month.lower()]
            if matching_budgets:
                filtered_groups.append({
                    **group, "budgets": matching_budgets,
                    "total_income": matching_budgets[0]['monthly_income'],
                    "total_expenses": matching_budgets[0]['total_expenses'],
                    "total_savings": matching_budgets[0]['savings']
                })

    if not filtered_groups:
        flash("No data found for this scope.", "error")
        return redirect(url_for('all_budgets'))

    # 3. Generate QuickCharts for all levels
    from urllib.parse import quote
    
    def generate_bar_chart(labels, data, colors=None):
        # Use default colors if none passed
        if not colors:
            colors = "['#4F46E5', '#EF4444', '#10B981']"

        config = f"""{{
            type: 'bar',
            data: {{
                labels: {labels},
                datasets: [{{
                    label: 'Amount (₹)',
                    data: {data},
                    backgroundColor: {colors},
                    borderRadius: 4,
                    barPercentage: 0.5
                }}]
            }},
            options: {{ 
                plugins: {{ legend: {{ display: false }} }}, 
                scales: {{ 
                    y: {{ beginAtZero: true }},
                    x: {{ grid: {{ display: false }} }}
                }} 
            }}
        }}"""
        return f"https://quickchart.io/chart?c={quote(config.replace(chr(10), '').replace(' ', ''))}&w=600&h=250&bkg=white"

    def generate_doughnut_chart(labels, data, colors):
        config = f"""{{
            type: 'doughnut',
            data: {{ labels: {labels}, datasets: [{{ data: {data}, backgroundColor: {colors} }}] }},
            options: {{ plugins: {{ legend: {{ position: 'bottom' }} }} }}
        }}"""
        return f"https://quickchart.io/chart?c={quote(config.replace(chr(10), '').replace(' ', ''))}&w=400&h=250&bkg=white"

    # Attach chart URLs to the data
    for group in filtered_groups:
        # Yearly Trend Chart (if more than 1 month)
        months = [b['month_word'] for b in reversed(group['budgets'])]
        inc = [b['monthly_income'] for b in reversed(group['budgets'])]
        exp = [b['total_expenses'] for b in reversed(group['budgets'])]
        sav = [b['savings'] for b in reversed(group['budgets'])]
        if len(months) > 1:
            group['trend_chart_url'] = generate_bar_chart(months, inc, exp, sav)

        # Monthly Charts
        for b in group['budgets']:
            # Bar Chart (Single dataset, 3 bars)
            b['bar_url'] = generate_bar_chart(
                "['Income', 'Expenses', 'Savings']", 
                f"[{b['monthly_income']}, {b['total_expenses']}, {b['savings']}]",
                "['#4F46E5', '#EF4444', '#10B981']"
            )
            # Income Allocation Chart
            b['alloc_url'] = generate_doughnut_chart(
                "['Expenses', 'Savings']", 
                f"[{b['total_expenses']}, {max(0, b['savings'])}]",
                "['#f43f5e', '#10b981']"
            )
            # Category Chart
            if b['category_totals']:
                cat_labels = list(b['category_totals'].keys())
                cat_vals = list(b['category_totals'].values())
                b['pie_url'] = generate_doughnut_chart(
                    str(cat_labels), str(cat_vals),
                    "['#818cf8', '#f472b6', '#fbbf24', '#34d399', '#a78bfa', '#22d3ee']"
                )

    # 4. Render Template
    logo_url = url_for('static', filename='icon/favicon.png', _external=True)
    
    html = render_template(
        'pdf_all_budgets.html',
        groups=filtered_groups,
        lifetime_income=lifetime_income,
        lifetime_expenses=lifetime_expenses,
        lifetime_savings=lifetime_savings,
        scope=scope,
        username=cleaned_username,
        now=datetime.now(IST),
        logo_url=logo_url
    )
    
    try:
        pdf = pdfkit.from_string(html, False, options=pdf_options, configuration=config)
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        
        timestamp = datetime.now(IST).strftime('%d_%b_%Y_%I-%M%p')
        
        if scope == 'monthly':
            safe_month = target_month.replace(' ', '_').lower()
            filename = f"budget_wisely_{safe_month}_monthly_report_{timestamp}.pdf"
        elif scope == 'yearly':
            filename = f"budget_wisely_{target_year}_yearly_report_{timestamp}.pdf"
        else:
            filename = f"budget_wisely_lifetime_report_{timestamp}.pdf"
        
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    except Exception as e:
        flash(f"PDF generation failed: {str(e)}", "error")
        return redirect(url_for('all_budgets'))
    
# Application Routes
@app.route('/')
def default():
    expiry_ts = session.get('session_expiry', 0)
    now_ts = datetime.now().timestamp()
    user_id = session.get('user_id')

    if user_id and now_ts <= expiry_ts:
        return redirect(url_for('dashboard'))

    session.clear()  # clean any stale cookie
    return redirect(url_for('landing_page'))

@app.route('/landing_page', methods=['GET'])
def landing_page():
    return render_template('Default.html')

@app.route("/dashboard", methods=["GET", "POST"])
@never_cache
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        user_id = int(session['user_id'])
    except (ValueError, TypeError):
        session.clear()
        return redirect(url_for('login'))

    expiry_timestamp = session.get('session_expiry', 0)
    current_time = datetime.now().timestamp()
    #remaining_seconds = max(0, int(expiry_timestamp - current_time))
 
    if current_time > expiry_timestamp:
        session.clear()
        flash('Session time expired! Please login again', 'error')
        return redirect(url_for('login')) 
    
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Fetch all budgets for the user
    budget_query = UserBudget.query.filter_by(user_id=user_id).order_by(UserBudget.id.desc())
    selected_month = session.get("selected_month")
    budget = None

    if selected_month:
        budget = budget_query.filter(
            func.lower(func.trim(UserBudget.month_name)) == selected_month.strip().lower()
        ).first()

    if not budget:
        budget = budget_query.first()
        if budget:
            session["selected_month"] = budget.month_name
        else:
            session.pop("selected_month", None)

    if budget:
        expenses = Expense.query.filter_by(budget_id=budget.id).order_by(Expense.date.desc(), Expense.id.desc()).all()
        total_expenses = sum(float(exp.expense_amount) for exp in expenses)
        savings = float(budget.monthly_income) - total_expenses

        # 👇 ADD THIS BLOCK HERE 👇
        category_totals = {}
        for exp in expenses:
            cat = exp.expense_category
            amt = float(exp.expense_amount)
            category_totals[cat] = category_totals.get(cat, 0) + amt
        # 👆 END OF NEW BLOCK 👆

        budget_result = {
            "month_name": budget.month_name,
            "monthly_income": float(budget.monthly_income),
            "total_expenses": total_expenses,
            "savings": savings,
            "category_totals": category_totals, # 👈 ADD THIS LINE
            "expenses": [{
                "id": exp.id,
                "category": exp.expense_category,
                "amount": float(exp.expense_amount),
                "dayname": exp.day_name,
                "date": exp.date
            } for exp in expenses]
        }
    else:
        budget_result = None

    return render_template("Index.html", 
                           username=user.name,
                           budget_result=budget_result, 
                           expiry_timestamp=int(expiry_timestamp * 1000)) # Pass milliseconds for JS

@app.route("/all-budgets", methods=["GET"])
@never_cache
def all_budgets():
    if 'user_id' not in session:
        flash('Session expired! Please login again', 'error')
        return redirect(url_for('login'))

    try:
        user_id = int(session['user_id'])
    except (ValueError, TypeError):
        session.clear()
        return redirect(url_for('login'))

    username = session.get('username')
    expiry_time = session.get('session_expiry', 0)
    current_time = datetime.now().timestamp()

    if current_time > expiry_time:
        session.clear()
        flash('Session time expired! Please login again', 'error')
        return redirect(url_for('login'))

    MONTH_ORDER = {
        'January': 1, 'February': 2, 'March': 3, 'April': 4,
        'May': 5, 'June': 6, 'July': 7, 'August': 8,
        'September': 9, 'October': 10, 'November': 11, 'December': 12
    }

    try:
        all_user_budgets = (
            UserBudget.query
            .filter_by(user_id=user_id)
            .order_by(UserBudget.id.desc())
            .all()
        )

        if not all_user_budgets:
            flash("No budget data found! Please add a month first.", "error")
            # ✅ Pass empty lifetime_stats when no data
            empty_stats = {
                "total_income": 0.0,
                "total_expenses": 0.0,
                "total_savings": 0.0,
                "expenses_percentage": 0.0,
                "savings_percentage": 0.0,
            }
            return render_template("Allbudgets.html", username=username, budgets_by_year=[], lifetime_stats=empty_stats)

        # ---- Build per-budget records + group by year ----
        groups = {}
        uncategorized = []

        for budget in all_user_budgets:
            expenses = Expense.query.filter_by(budget_id=budget.id).order_by(Expense.date.desc(), Expense.id.desc()).all()

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
                    "month_name": exp.month_name,
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

            # 👇 ADD THIS BLOCK HERE 👇
            category_totals = {}
            for item in expense_items:
                cat = item["category"]
                amt = item["amount"]
                category_totals[cat] = category_totals.get(cat, 0) + amt
            # 👆 END OF NEW BLOCK 👆

            raw_month = (budget.month_name or "").strip()
            parts = raw_month.split()
            month_word = parts[0] if parts else ""
            year_val = None
            for token in parts[1:]:
                if token.isdigit():
                    year_val = int(token)
                    break

            record = {
                "id": budget.id,
                "month_name": raw_month,
                "month_word": month_word,
                "month_num": MONTH_ORDER.get(month_word, 0),
                "year": year_val,
                "monthly_income": float(budget.monthly_income),
                "total_expenses": total_expenses,
                "savings": savings,
                "savings_percentage": round((savings / float(budget.monthly_income)) * 100, 2)
                                     if float(budget.monthly_income) > 0 else 0,
                "category_totals": category_totals, # 👈 ADD THIS LINE
                "expenses": expense_items,
                "expense_percentages": expense_percentages
            }

            if year_val is None:
                uncategorized.append(record)
            else:
                groups.setdefault(year_val, []).append(record)

        # ---- Build the final ordered structure ----
        budgets_by_year = []

        for year in sorted(groups.keys(), reverse=True):
            year_budgets = groups[year]

            year_budgets.sort(
                key=lambda b: (b["month_num"], b["id"]),
                reverse=True
            )

            total_income = sum(b["monthly_income"] for b in year_budgets)
            total_exp = sum(b["total_expenses"] for b in year_budgets)
            total_sav = total_income - total_exp

            budgets_by_year.append({
                "label": str(year),
                "year": year,
                "is_uncategorized": False,
                "budgets": year_budgets,
                "total_income": total_income,
                "total_expenses": total_exp,
                "total_savings": total_sav,
                "expenses_percentage": round((total_exp / total_income) * 100, 2)
                                      if total_income > 0 else 0,
                "savings_percentage": round((total_sav / total_income) * 100, 2)
                                      if total_income > 0 else 0,
            })

        if uncategorized:
            uncategorized.sort(key=lambda b: (b["month_num"], b["id"]), reverse=True)
            total_income = sum(b["monthly_income"] for b in uncategorized)
            total_exp = sum(b["total_expenses"] for b in uncategorized)
            total_sav = total_income - total_exp
            budgets_by_year.append({
                "label": "Uncategorized",
                "year": None,
                "is_uncategorized": True,
                "budgets": uncategorized,
                "total_income": total_income,
                "total_expenses": total_exp,
                "total_savings": total_sav,
                "expenses_percentage": round((total_exp / total_income) * 100, 2)
                                      if total_income > 0 else 0,
                "savings_percentage": round((total_sav / total_income) * 100, 2)
                                      if total_income > 0 else 0,
            })

        # ✅ NEW: Calculate Lifetime Stats across all years
        lifetime_income = sum(g['total_income'] for g in budgets_by_year)
        lifetime_expenses = sum(g['total_expenses'] for g in budgets_by_year)
        lifetime_savings = lifetime_income - lifetime_expenses

        lifetime_stats = {
            "total_income": lifetime_income,
            "total_expenses": lifetime_expenses,
            "total_savings": lifetime_savings,
            "expenses_percentage": round((lifetime_expenses / lifetime_income) * 100, 2)
                                   if lifetime_income > 0 else 0,
            "savings_percentage": round((lifetime_savings / lifetime_income) * 100, 2)
                                  if lifetime_income > 0 else 0,
        }

        return make_response(render_template(
            "Allbudgets.html",
            username=username,
            budgets_by_year=budgets_by_year,
            lifetime_stats=lifetime_stats,  # 👈 PASS LIFETIME STATS
            now=datetime.now()
        ))

    except Exception as e:
        app.logger.exception("all_budgets failed")
        flash(f"Error retrieving budget data: {str(e)}", "error")
        return render_template("Allbudgets.html", username=username, budgets_by_year=[], lifetime_stats={
            "total_income": 0.0, "total_expenses": 0.0, "total_savings": 0.0,
            "expenses_percentage": 0.0, "savings_percentage": 0.0,
        })

@app.route('/vault', methods=['GET', 'POST'])
@never_cache
def vault():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = db.session.get(User, session['user_id'])
    
    # --- 1. If User hasn't set a PIN yet, redirect to setup ---
    if not user.vault_pin:
        flash("Please set up a Vault PIN first.", "info")
        return redirect(url_for('vault_setup'))

    # --- 2. Check if Vault is Unlocked ---
    is_unlocked = session.get('vault_unlocked', False)

    # --- 3. Handle PIN Submission ---
    if request.method == 'POST' and not is_unlocked:
        entered_pin = request.form.get('pin', '').strip()
        if check_password_hash(user.vault_pin, entered_pin):
            session['vault_unlocked'] = True
            return redirect(url_for('vault'))
        else:
            flash("Incorrect Vault PIN!", "error")
            return redirect(url_for('vault'))

    # --- 4. Load Data if Unlocked ---
    vault_items = []
    if is_unlocked:
        vault_items = VaultItem.query.filter_by(user_id=user.user_id).order_by(VaultItem.created_at.desc()).all()
        # Convert times to IST for the template
        for item in vault_items:
            item.created_ist = to_ist(item.created_at).strftime('%d %b %Y, %I:%M %p')
            if item.updated_at and item.updated_at != item.created_at:
                item.updated_ist = to_ist(item.updated_at).strftime('%d %b %Y, %I:%M %p')
            else:
                item.updated_ist = None

    return render_template('Vault.html', user=user, is_unlocked=is_unlocked, items=vault_items)

@app.route('/vault/setup', methods=['GET', 'POST'])
@never_cache
def vault_setup():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    
    if request.method == 'POST':
        account_pass = request.form.get('account_pass', '').strip()
        new_pin = request.form.get('new_pin', '').strip()

        if not check_password_hash(user.password, account_pass):
            flash("Incorrect account password.", "error")
        elif len(new_pin) < 4:
            flash("PIN must be at least 4 characters.", "error")
        else:
            user.vault_pin = generate_password_hash(new_pin)
            db.session.commit()
            session['vault_unlocked'] = True # Auto-unlock after setup
            flash("Vault created successfully!", "success")
            return redirect(url_for('vault'))
            
    return render_template('VaultSetup.html')

from flask import jsonify  # Make sure this is imported at the top

@app.route('/vault/reset-pin', methods=['POST'])
def vault_reset_pin():
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Session expired. Please log in again."}), 401
    
    user = db.session.get(User, session['user_id'])
    account_pass = request.form.get('account_pass', '').strip()
    new_pin = request.form.get('new_pin', '').strip()

    # 1. Verify Account Password
    if not check_password_hash(user.password, account_pass):
        # Return JSON error instead of redirecting
        return jsonify({"success": False, "error": "Incorrect account password. PIN not reset."}), 400

    # 2. Validate New PIN Length
    if len(new_pin) < 4:
        return jsonify({"success": False, "error": "PIN must be at least 4 characters."}), 400

    # 3. Update PIN, Unlock Vault
    user.vault_pin = generate_password_hash(new_pin)
    db.session.commit()
    
    session['vault_unlocked'] = True
    
    # Return success JSON
    return jsonify({"success": True, "message": "Vault PIN reset successfully! Unlocking..."}), 200

@app.route('/vault/lock')
def vault_lock():
    session.pop('vault_unlocked', None)
    flash("Vault locked securely.", "info")
    return redirect(url_for('vault'))

@app.route('/vault/add', methods=['POST'])
def vault_add():
    if not session.get('vault_unlocked'): return redirect(url_for('vault'))
    
    title = request.form.get('title', '').strip()
    secret = request.form.get('secret_text', '').strip()
    
    if title and secret:
        new_item = VaultItem(user_id=session['user_id'], title=title, secret_text=secret)
        db.session.add(new_item)
        db.session.commit()
        flash("Secret saved to Vault!", "success")
    else:
        flash("Title and Secret text are required.", "error")
        
    return redirect(url_for('vault'))

@app.route('/vault/edit/<int:item_id>', methods=['POST'])
def vault_edit(item_id):
    if not session.get('vault_unlocked'): 
        return redirect(url_for('vault'))
        
    item = VaultItem.query.get_or_404(item_id)
    
    # Security check: Ensure the item belongs to the logged-in user
    if item.user_id == session['user_id']:
        title = request.form.get('title', '').strip()
        secret = request.form.get('secret_text', '').strip()
        
        if title and secret:
            item.title = title
            item.secret_text = secret
            db.session.commit()
            flash("Secret updated successfully!", "success")
        else:
            flash("Title and Secret text cannot be empty.", "error")
            
    return redirect(url_for('vault'))

@app.route('/vault/delete/<int:item_id>')
def vault_delete(item_id):
    if not session.get('vault_unlocked'): return redirect(url_for('vault'))
    item = VaultItem.query.get_or_404(item_id)
    if item.user_id == session['user_id']:
        db.session.delete(item)
        db.session.commit()
        flash("Secret deleted.", "success")
    return redirect(url_for('vault'))

@app.route('/profile')
@never_cache
def profile():
    if 'user_id' not in session:
        flash("Session expired! Please login again.", 'error')
        return redirect(url_for('login'))

    user_id = int(session['user_id'])
    user = db.session.get(User, user_id)
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # 1. Calculate Account Age (Dynamically hide 0 values)
    delta = relativedelta(datetime.utcnow(), user.created_at)
    
    age_parts = []
    if delta.years > 0:
        age_parts.append(f"{delta.years}yr{'s' if delta.years > 1 else ''}")
    if delta.months > 0:
        age_parts.append(f"{delta.months}month{'s' if delta.months > 1 else ''}")
    if delta.days > 0:
        age_parts.append(f"{delta.days}day{'s' if delta.days > 1 else ''}")
        
    # If the list is empty (meaning 0 days), show "Today"
    account_age = " ".join(age_parts) if age_parts else "Joined Today"

    # 2. Calculate Accurate Lifetime Stats
    budgets = UserBudget.query.filter_by(user_id=user_id).all()
    total_income = sum(float(b.monthly_income) for b in budgets)
    
    expenses = Expense.query.filter_by(user_id=user_id).all()
    total_expenses = sum(float(e.expense_amount) for e in expenses)
    
    stats = {
        "total_income": total_income,
        "total_expenses": total_expenses,
        "total_savings": total_income - total_expenses,
        "months_count": len(budgets)
    }

    return render_template('Profile.html', user=user, stats=stats, account_age=account_age)

@app.route('/settings')
@never_cache
def settings():
    if 'user_id' not in session:
        flash("Session expired! Please login again.", 'error')
        return redirect(url_for('login'))
    return render_template('Settings.html')
    
@app.route('/add_month', methods=['POST'])
def add_month():
    if 'user_id' not in session:
        flash('You must login to do this task!', 'error')
        return redirect(url_for('login'))

    username = session.get('username')
    try:
        user_id = int(session.get('user_id'))
    except (ValueError, TypeError):
        flash('Session invalid. Please login again.', 'error')
        return redirect(url_for('login'))

    date = request.form.get("date", "").strip()
    raw_income = request.form.get("income", "").strip()

    if not date or not raw_income:
        flash('All fields are required!', 'error')
        return redirect(url_for('dashboard'))

    try:
        monthly_income = float(raw_income)
        if monthly_income <= 0.0:
            flash('Monthly income must be positive!', 'error')
            return redirect(url_for('dashboard'))
    except ValueError:
        flash('Invalid income amount!', 'error')
        return redirect(url_for('dashboard'))

    try:
        date_obj = datetime.strptime(date, "%Y-%m-%d")
        month_name = date_obj.strftime("%B %Y").strip()   # e.g. "February 2026"
    except ValueError:
        flash("Invalid date format!", 'error')
        return redirect(url_for('dashboard'))

    try:
        session["selected_month"] = month_name  

        user_budget = UserBudget.query.filter(
            UserBudget.user_id == user_id,
            func.lower(func.trim(UserBudget.month_name)) == month_name.lower()
        ).first()

        if user_budget:
            user_budget.monthly_income = monthly_income
            expenses = Expense.query.filter_by(budget_id=user_budget.id).all()
            total_exp = sum(float(exp.expense_amount) for exp in expenses)
            user_budget.total_expenses = total_exp
            user_budget.savings = monthly_income - total_exp
            db.session.commit() 
            flash('Month & Monthly income updated successfully!', 'success')
        else:
            new_budget = UserBudget(
                user_id=user_id, 
                username=username or '', 
                month_name=month_name, 
                monthly_income=monthly_income,
                total_expenses=0.0,
                savings=monthly_income
            )
            db.session.add(new_budget)
            db.session.commit()
            flash('Month & Monthly income added successfully!', 'success')
            
        return redirect(url_for('dashboard'))

    except Exception as e:
        db.session.rollback()
        flash(f"Database error: {str(e)}", 'error')
        return redirect(url_for('dashboard'))

@app.route('/edit_expense', methods=['POST'])
def edit_expense():
    if 'user_id' not in session:
        flash("Please log in to make changes.", 'error')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    expense_id = request.form.get('expense_id')
    raw_category = request.form.get('category', '').strip()
    raw_amount = request.form.get('amount', '').strip()
    date_str = request.form.get('date', '').strip()
    target_page = request.form.get('target_page', '').strip() or 'dashboard'

    if not raw_category or not raw_amount or not date_str:
        flash("Please enter all fields.", 'error')
        return redirect(url_for(target_page))

    try:
        # 1. Validate Amount
        new_amount = float(raw_amount)
        if new_amount < 0:
            flash("Please enter a valid positive expense amount.", 'error')
            return redirect(url_for(target_page))

        # 2. Validate Category Length
        if len(raw_category) > 100:
            flash("Expense category is too long (max 100 characters).", 'error')
            return redirect(url_for(target_page))

        # 3. Validate Date Format & Boundaries (IST)
        try:
            new_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", 'error')
            return redirect(url_for(target_page))

        today_ist = datetime.now(IST).date()

        if new_date > today_ist:
            flash("Expense date cannot be in the future.", 'error')
            return redirect(url_for(target_page))

        if new_date < today_ist - timedelta(days=365 * 5):
            flash("Expense date cannot be older than 5 years.", 'error')
            return redirect(url_for(target_page))

        if new_date.year < 2000:
            flash("Expense date cannot be before the year 2000.", 'error')
            return redirect(url_for(target_page))

    except Exception as e:
        flash(f"Validation error: {str(e)}", 'error')
        return redirect(url_for(target_page))

    try:
        expense = db.session.get(Expense, int(expense_id)) if expense_id else None

        if not expense or int(expense.user_id) != int(user_id):
            flash('Expense record not found.', 'error')
            return redirect(url_for(target_page))

        # 4. Fetch the parent budget to check the correct month
        budget = UserBudget.query.get(expense.budget_id)
        if not budget:
            flash('Parent budget not found.', 'error')
            return redirect(url_for(target_page))

        # 5. Validate that the new date falls within the SAME month as the budget
        # Build the expected month name from the new date (e.g., "March 2026")
        new_month_name = new_date.strftime("%B %Y").strip()

        if new_month_name.lower() != budget.month_name.lower():
            flash(
                f"Date error: You are editing an expense inside the '{budget.month_name}' budget. "
                f"Your new date ({new_date.strftime('%d %b %Y')}) belongs to '{new_month_name}'. "
                f"Please select a date within {budget.month_name}.",
                'error'
            )
            return redirect(url_for(target_page))

        # 6. Check for no changes
        if (
            expense.expense_category == raw_category and
            float(expense.expense_amount) == new_amount and
            expense.date == new_date
        ):
            flash('No changes were made to the expense.', 'info')
            return redirect(url_for(target_page))

        # 7. Apply all updates (including date fields)
        expense.expense_category = raw_category
        expense.expense_amount = new_amount
        expense.date = new_date
        expense.day_name = new_date.strftime("%A")
        expense.month_name = new_month_name  # (Same as budget.month_name)

        # 8. Recalculate budget totals
        expenses = Expense.query.filter_by(budget_id=budget.id).all()
        budget.total_expenses = sum(float(exp.expense_amount) for exp in expenses)
        budget.savings = float(budget.monthly_income) - float(budget.total_expenses)

        db.session.commit()
        flash('Expense updated successfully!', 'success')

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

    if not month_name or not raw_income:
        flash("Missing month or income value.", 'error')
        return redirect(url_for(target_page))

    try:
        new_income = float(raw_income)
        if new_income < 0:
            flash("Please enter a valid income amount.", 'error')
            return redirect(url_for(target_page))
    except ValueError:
        flash("Invalid income value entered.", 'error')
        return redirect(url_for(target_page))

    try:
        budget = UserBudget.query.filter(
            UserBudget.user_id == int(user_id),
            func.lower(func.trim(UserBudget.month_name)) == month_name.lower()
        ).first()

        if budget:
            if float(budget.monthly_income) == new_income:
                flash('No changes were made to monthly income.', 'info')
            else:
                budget.monthly_income = new_income
                expenses = Expense.query.filter_by(budget_id=budget.id).all()
                total_exp = sum(float(exp.expense_amount) for exp in expenses)
                budget.total_expenses = total_exp
                budget.savings = new_income - total_exp
                db.session.commit()
                flash('Monthly income updated successfully!', 'success')
        else:
            flash(f'No budget exists for {month_name}. Please add a budget first.', 'error')

    except Exception as e:
        db.session.rollback()
        flash(f'Failed to update income: {str(e)}', 'error')

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
        user_id = int(session.get('user_id'))

        if not all([date_str, exp_category, exp_amount]):
            flash('All fields are required!', 'error')
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
            month_name = date_obj.strftime("%B %Y").strip()       # ✅ "February 2026"
            day_name = date_obj.strftime("%A")
        except ValueError:
            flash('Invalid date format! Please use YYYY-MM-DD.', 'error')
            return redirect(url_for(target_page))

        target_month_name = request.form.get('month_name', '').strip()
        if target_month_name and target_month_name.lower() != month_name.lower():
            flash(f"Date error: You selected a date in {month_name}, but you are adding an expense inside the {target_month_name} block!", "error")
            return redirect(url_for(target_page))

        budget = UserBudget.query.filter(
            UserBudget.user_id == user_id,
            func.lower(func.trim(UserBudget.month_name)) == month_name.lower()
        ).first()

        if not budget:
            msg = (
                f"Please create a budget for {month_name} using the 'Budget Controls' section on the left."
                if flag == 'index'
                else f"No budget exists for {month_name}. Please add a budget for {month_name} first."
            )
            flash(msg, "error")
            return redirect(url_for(target_page))

        new_expense = Expense(
            user_id=user_id,
            budget_id=budget.id,
            day_name=day_name,
            month_name=month_name,
            date=date_obj.date(),
            expense_category=exp_category,
            expense_amount=exp_amount
        )
        db.session.add(new_expense)
        db.session.commit()

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

@app.route('/delete_month', methods=['POST'])
def delete_month():
    # ---- 1. Authentication check ----
    if 'user_id' not in session:
        flash("Session expired! Please login again.", 'error')
        return redirect(url_for('login'))

    # ---- 2. Session integrity check ----
    try:
        user_id = int(session['user_id'])
    except (ValueError, TypeError, KeyError):
        session.clear()
        flash("Invalid session. Please login again.", 'error')
        return redirect(url_for('login'))

    # ---- 3. Session expiry check (matches your other routes) ----
    expiry_timestamp = session.get('session_expiry', 0)
    if datetime.now().timestamp() > expiry_timestamp:
        session.clear()
        flash("Session time expired! Please login again.", 'error')
        return redirect(url_for('login'))

    # ---- 4. Validate input ----
    flag = request.form.get('flag', '').strip()
    month_name = request.form.get('month_name', '').strip()
    if not month_name:
        flash("No month specified for deletion.", 'error')
        return redirect(url_for('dashboard'))

    try:
        # ---- 5. Find the budget (scoped to this user only) ----
        budget = UserBudget.query.filter(
            UserBudget.user_id == user_id,
            func.lower(func.trim(UserBudget.month_name)) == month_name.lower()
        ).first()

        if not budget:
            flash(f"No budget found for {month_name}.", 'error')
            return redirect(url_for('dashboard'))

        # ---- 6. Explicit expense cleanup (don't rely only on cascade) ----
        # Your relationship has cascade='all, delete-orphan', but being explicit
        # is safer across DB backends (MySQL/Postgres) and avoids orphans.
        Expense.query.filter_by(budget_id=budget.id).delete(synchronize_session=False)

        # ---- 7. Delete the budget row ----
        db.session.delete(budget)
        db.session.commit()

        # ---- 8. Clear any stale session state ----
        if session.get('selected_month', '').lower() == month_name.lower():
            session.pop('selected_month', None)

        flash(f"Budget for {month_name} deleted successfully!", 'success')

    except Exception as e:
        db.session.rollback()
        # Log the real error server-side; show a safe message to the user
        app.logger.exception(f"delete_month failed for user {user_id}, month {month_name}")
        flash(f"Failed to delete budget: {str(e)}", 'error')
    if flag == 'index':
        return redirect(url_for('dashboard'))
    return redirect(url_for('all_budgets'))

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
            
            if owner_id is not None and int(owner_id) == int(user_id):
                budget_id = expense.budget_id
                
                db.session.delete(expense)
                db.session.commit()

                budget = UserBudget.query.get(budget_id)
                if budget:
                    expenses = Expense.query.filter_by(budget_id=budget.id).all()
                    budget.total_expenses = sum(float(exp.expense_amount) for exp in expenses)
                    budget.savings = float(budget.monthly_income) - float(budget.total_expenses)
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
import os
import smtplib
from collections import defaultdict
from datetime import datetime
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
                    # 1. Fetch current month data and formatted date
                    now = datetime.now()
                    current_month_name = now.strftime("%B %Y")   # ✅ "August 2026"
                    formatted_date = now.strftime("%b %d")    # e.g., "Aug 11"

                    budget = UserBudget.query.filter_by(
                        user_id=user.user_id, 
                        month_name=current_month_name
                    ).first()

                    expenses = Expense.query.filter_by(
                        user_id=user.user_id,
                        month_name=current_month_name
                    ).order_by(Expense.date.desc()).all()

                    monthly_income = float(budget.monthly_income) if (budget and budget.monthly_income) else 0.00

                    # 2. Build inner content based on budget existence
                    if monthly_income <= 0:
                        # --- NO BUDGET SET CONTENT ---
                        main_content_html = f"""
                        <div style="background-color: #0f172a; border: 1px dashed #f59e0b; border-radius: 12px; padding: 24px; text-align: center; margin: 20px 0;">
                            <p style="margin: 0 0 8px 0; font-size: 15px; color: #fbbf24; font-weight: 700;">
                                ⚠️ No Monthly Budget Set for {current_month_name}
                            </p>
                            <p style="margin: 0 0 18px 0; font-size: 13px; color: #94a3b8; line-height: 1.5;">
                                You haven't configured your budget for this month yet. Add your monthly income now to start logging expenses and tracking your financial goals!
                            </p>
                            <a href="{app_url}" style="background-color: #f59e0b; color: #0f172a; padding: 10px 22px; text-decoration: none; border-radius: 8px; font-size: 13px; font-weight: bold; display: inline-block;">
                                Set Monthly Budget
                            </a>
                        </div>
                        """
                    else:
                        # --- FULL REPORT CONTENT ---
                        total_expenses = sum(float(e.expense_amount) for e in expenses)
                        net_savings = monthly_income - total_expenses
                        
                        savings_percent = round((net_savings / monthly_income) * 100, 1)
                        expense_percent = round((total_expenses / monthly_income) * 100, 1)
                        savings_color = "#27ae60" if net_savings >= 0 else "#e74c3c"

                        # Aggregate Expenses by Category
                        cat_totals = defaultdict(float)
                        for exp in expenses:
                            cat_totals[exp.expense_category] += float(exp.expense_amount)

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

                        # Recent Transactions Table
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

                        # Combine Full Report View
                        main_content_html = f"""
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

                        {chart_html}
                        {expense_table_html}

                        <div style="text-align: center; margin-top: 28px;">
                            <a href="{app_url}" style="background-color: #22c55e; color: #ffffff; padding: 12px 28px; text-decoration: none; border-radius: 10px; font-size: 13px; font-weight: bold; display: inline-block; box-shadow: 0 4px 12px rgba(34, 197, 94, 0.3);">
                                Control Your Budget
                            </a>
                        </div>
                        """

                    # 3. Outer Master HTML Wrapper
                    html_body = f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    </head>
                    <body style="margin: 0; padding: 0; background-color: #0b1120; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
                        <table style="width: 100%; background-color: #0b1120; margin: 0; padding: 40px 10px;" cellpadding="0" cellspacing="0" border="0">
                            <tr>
                                <td align="center">
                                    <table style="max-width: 540px; width: 100%; background-color: #1e293b; border-radius: 16px; border: 1px solid #334155; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);" cellpadding="0" cellspacing="0" border="0">
                                        <tr>
                                            <td style="padding: 32px 24px;">
                                                <div style="text-align: center; margin-bottom: 24px;">
                                                    <h1 style="margin: 0; font-size: 24px; color: #ffffff; font-weight: 800; letter-spacing: -0.5px;">💰 Budget Wisely</h1>
                                                    <p style="margin: 6px 0 0 0; font-size: 13px; color: #94a3b8;">Weekly Financial Digest • {current_month_name}</p>
                                                </div>

                                                <p style="font-size: 14px; color: #e2e8f0; margin-bottom: 20px; line-height: 1.5;">
                                                    Hi <strong>{user.name}</strong>, here is your financial summary for {current_month_name}:
                                                </p>

                                                <!-- Dynamic Content Insertion -->
                                                {main_content_html}

                                                <div style="height: 1px; background-color: #334155; margin: 28px 0 16px 0;"></div>
                                                <p style="font-size: 11px; color: #94a3b8; text-align: center; margin: 0;">
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

                    # 4. Message Dispatch
                    msg = MIMEMultipart("alternative")
                    msg['From'] = sender_email
                    msg['To'] = user.email
                    msg['Subject'] = f"📈 Budget Summary - {formatted_date} - Budget Wisely"
                    
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
@never_cache
def signup():
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Helper for AJAX errors
        def signup_error(message):
            flash(message, "error")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': message})
            return redirect(url_for('signup'))

        # Validate inputs
        if password != confirm_password:
            return signup_error("Passwords don't match!")
            
        elif password and password[0].isdigit():
            return signup_error("Password must start with a letter!")
            
        elif len(password) < 6:
            return signup_error("Password too short (min 6 chars)!")
            
        else:
            try:
                validate_email(email)
                
                if User.query.filter_by(email=email).first():
                    return signup_error("Email already exists!")
                else:
                    new_user = User(
                        name=name,
                        email=email,
                        password=generate_password_hash(password),
                        created_at=datetime.utcnow()
                    )
                    db.session.add(new_user)
                    db.session.commit()
                    
                    flash("Registration successful! Please login.", 'success')
                    
                    # 👇 AJAX SUCCESS CHECK 👇
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({'success': True, 'redirect': url_for('login')})
                        
                    return redirect(url_for('login'))
            
            except EmailNotValidError as e:
                return signup_error(str(e))
                
            except Exception as e:
                db.session.rollback()
                return signup_error(f"Database error: {str(e)}")
        
        return redirect(url_for('signup'))

    return render_template('Signup.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
@never_cache
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = User.query.filter_by(email=email).first()

        # Helper function
        def forgot_error(message):
            flash(message, "error")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': message})
            return redirect(url_for('forgot_password'))

        if user:
            if send_otp(email):
                flash("OTP sent successfully!", "success")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': True, 'redirect': url_for('verify_otp')})
                return redirect(url_for('verify_otp'))
            else:
                return forgot_error("Failed to send OTP. Try again later.")
        else:
            return forgot_error("No account found with this email!")
                
    return render_template('Forgotpass.html')

from flask import request, jsonify

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
                session.clear()
                session['user_id'] = user.user_id
                session['username'] = user.name
                session.permanent = True

                expiry_time = datetime.now() + timedelta(minutes=60)
                session['session_expiry'] = expiry_time.timestamp()
                
                # 👇 AJAX SUCCESS: Return JSON
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': True, 'redirect': url_for('dashboard')})
                
                flash("Login successful!", 'success')
                return redirect(url_for("dashboard"))
            
            # 👇 ADD FLASH MESSAGE BEFORE THE AJAX RESPONSE 👇
            flash("Invalid email or password", 'error') 
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False}), 200
            
        except Exception as e:
            flash(f"Database error: {str(e)}", "error")
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False}), 200
        
        return redirect(url_for("login"))

    return render_template('Login.html')

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
    
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header

def send_otp(email):
    print("Sender:", os.getenv("SENDER_EMAIL"))
    otp = random.randint(100000, 999999)
    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASS')

    if not sender_email or not sender_password:
        print("Error: Email credentials not set")
        return False
    
    # --- Professional Subject ---
    subject = "Budget Wisely | Password Reset Verification Code"
    
    # --- Professional Body (HTML) ---
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
        <h2 style="color: #4f46e5;">Password Reset Request</h2>
        <p>Hi,</p>
        <p>We received a request to reset your password for your <strong>Budget Wisely</strong> account.</p>
        <p>Your One-Time Password (OTP) is:</p>
        <p style="font-size: 28px; font-weight: bold; letter-spacing: 4px; text-align: center; background: #f1f5f9; padding: 15px; border-radius: 8px; color: #0f172a;">
          {otp}
        </p>
        <p><strong>This OTP is valid for 10 minutes.</strong></p>
        <p>If you did not request this, please ignore this email. Your account is safe.</p>
        <br>
        <p style="font-size: 0.85em; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 10px;">
          © 2026 Budget Wisely. All rights reserved.
        </p>
      </body>
    </html>
    """
    
    # --- Build the Message ---
    msg = MIMEMultipart('alternative')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = f"Budget Wisely <{sender_email}>"
    msg['To'] = email

    # Attach both plain text and HTML versions
    plain_text = f"Your OTP for password reset is: {otp}. It is valid for 10 minutes. If you did not request this, please ignore this email."
    msg.attach(MIMEText(plain_text, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())
            print(email)
            print(otp)
            session['email'] = email
            session['sent_otp'] = otp
            session['otp_expiry'] = (datetime.now() + timedelta(minutes=10)).timestamp()
            return True
    except Exception as e:
        print(f"Error sending OTP email: {e}")
        return False

# Verify OTP Route
@app.route('/verify_otp', methods=['GET', 'POST'])
@never_cache
def verify_otp():
    email = session.get('email')
    sent_otp = session.get('sent_otp')
    otp_expiry = session.get('otp_expiry')

    # Helper function for AJAX/Standard responses
    def otp_error(message, redirect_endpoint='forgot_password'):
        session.clear()
        flash(message, "error")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': message})
        return redirect(url_for(redirect_endpoint))

    if not email: return otp_error("Session expired! Please request for new otp.")
    if not sent_otp: return otp_error("OTP expired! Please request for new otp.")
    if not otp_expiry: return otp_error("OTP expiry not found! Please request for new otp.")
        
    if datetime.now().timestamp() > otp_expiry:
        return otp_error("OTP has expired! Please request a new one.")

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()

        if str(sent_otp) == entered_otp:
            session.pop('sent_otp', None)
            session.pop('otp_expiry', None)
            session.pop('email', None)
            session['verified_email'] = email

            flash("OTP verified successfully! Please reset your password.", "success")
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'redirect': url_for('reset_password')})
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid OTP! Please try again.", "error")
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': "Invalid OTP! Please try again."})
            return redirect(url_for('verify_otp'))

    return render_template('VerifyOTP.html')

# Reset Password using OTP
@app.route('/reset_password', methods=['GET', 'POST'])
@never_cache
def reset_password():
    email = session.get('verified_email')
    
    if not email:
        session.clear()
        flash('OTP expired! Please verify with OTP first.', 'error')
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'OTP expired! Please verify with OTP first.'})
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        cpassword = request.form.get('cpassword', '').strip()

        def pass_error(message):
            flash(message, 'error')
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': message})
            return render_template('Resetpass.html')

        if not password or not cpassword:
            return pass_error('Password fields cannot be empty!')
        elif password[0].isdigit():
            return pass_error("Password must start with a letter!")
        elif len(password) < 6:
            return pass_error("Password too short (min 6 chars)!")
        elif password != cpassword:
            return pass_error('Passwords do not match! Please try again.')
        else:
            try:
                user = User.query.filter_by(email=email).first()
                if user:
                    user.password = generate_password_hash(password)
                    db.session.commit()

                    session.pop('verified_email', None)
                    session.clear()
                    
                    flash("Password reset successful! Please log in.", "success")
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({'success': True, 'redirect': url_for('login')})
                    return redirect(url_for('login'))
                else:
                    session.clear()
                    return pass_error("User not found! Please try again.")
            except Exception as e:
                db.session.rollback()
                session.clear()
                return pass_error("We are unable to process your request right now. Please try again later.")
                
    return render_template('Resetpass.html')

@app.route('/change_password', methods=['GET', 'POST'])
@never_cache
def change_pass():
    if 'user_id' not in session:
        flash("Session expired! Please login again.", 'error')
        return redirect(url_for('login'))

    try:
        user_id = int(session['user_id'])
    except (ValueError, TypeError):
        session.clear()
        flash("Invalid session state. Please log in again.", "error")
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    if not user:
        session.clear()
        flash("User context not found! Please login again.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        oldpassword = request.form.get('oldpassword', '').strip()
        newpassword = request.form.get('newpassword', '').strip()
        cpassword = request.form.get('cpassword', '').strip()

        # 1. Check for empty inputs
        if not oldpassword or not newpassword or not cpassword:
            flash('All password fields are required!', 'error')

        # 2. Verify current/old password
        elif not check_password_hash(user.password, oldpassword):
            flash('Incorrect current password!', 'error')

        # 3. Validation on new password rules
        elif newpassword[0].isdigit():
            flash("New password must start with a letter!", "error")
        elif len(newpassword) < 6:
            flash("New password must be at least 6 characters long!", "error")
        elif newpassword != cpassword:
            flash('New passwords do not match! Please verify and try again.', 'error')
        elif oldpassword == newpassword:
            flash('New password cannot be the same as your current password!', 'error')

        # 4. Save updated password
        else:
            try:
                user.password = generate_password_hash(newpassword)
                db.session.commit()
                flash("Password updated successfully!", "success")
                return redirect(url_for('dashboard'))

            except Exception as e:
                db.session.rollback()
                flash("Unable to update password right now. Please try again later.", "error")

    return render_template('Changepass.html', username=user.name)
    
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

#====================
# Logout Route for clearing session for manual logout and session expiration
#====================

@app.route('/logout')
def logout():
    session.clear()  # Clears all session keys at once
    
    # Check if the flag was passed in the URL
    if request.args.get('expired') == 'true':
        flash("Your session has expired. Please login again.", "error") # Red/Warning
    else:
        flash("Logged out successfully!", "success") # Green/Success
        
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

# Reads "True"/"False" from environment, defaults to False
DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 'yes')

if __name__ == '__main__':
    app.run(debug=False, use_reloader=True)
