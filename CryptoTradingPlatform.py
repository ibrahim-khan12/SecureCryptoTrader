import sqlite3
import os
import secrets
import logging
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import json
import random

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size
app.config['UPLOAD_FOLDER'] = 'crypto_uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'jpg', 'jpeg', 'png'}

# Session timeout (5 minutes)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

DATABASE = 'crypto_platform.db'

# Logging setup
logging.basicConfig(
    filename='crypto_trading.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Encryption key management
def get_encryption_key():
    key_file = 'crypto_key.key'
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
    with open(key_file, 'rb') as f:
        return Fernet(f.read())

cipher = get_encryption_key()

# Mock crypto prices
CRYPTO_PRICES = {
    'BTC': 43250.50,
    'ETH': 2285.75,
    'BNB': 315.80,
    'SOL': 98.45,
    'ADA': 0.52,
    'DOT': 7.35,
    'MATIC': 0.85,
    'LINK': 14.75
}

# Security validation functions
def validate_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def sanitize_input(input_string):
    if not input_string:
        return ""
    sanitized = re.sub(r'[<>"\'/]', '', str(input_string))
    if re.search(r'(--|;|\'|\"|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)', 
                 sanitized, re.IGNORECASE):
        return ""
    return sanitized.strip()

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_numeric(value, min_val=0, max_val=None):
    try:
        num_val = float(value)
        if num_val < min_val:
            return False, f"Value must be at least {min_val}"
        if max_val and num_val > max_val:
            return False, f"Value must not exceed {max_val}"
        return True, num_val
    except (ValueError, TypeError):
        return False, "Invalid numeric value"

def validate_input_length(text, max_length=200):
    if len(text) > max_length:
        return False, f"Input too long (max {max_length} characters)"
    return True, text

def encrypt_data(data):
    if not data:
        return ""
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    if not encrypted_data:
        return ""
    try:
        return cipher.decrypt(encrypted_data.encode()).decode()
    except:
        return "[Decryption Failed]"

def log_audit(user_id, action, details, ip_address):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO audit_logs (user_id, action, details, ip_address)
                       VALUES (?, ?, ?, ?)''',
                     (user_id, action, details, ip_address))
            conn.commit()
        logging.info(f"User {user_id}: {action} - {details} - IP: {ip_address}")
    except Exception as e:
        logging.error(f"Audit logging failed: {str(e)}")

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def check_session_timeout():
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now() - last_activity > timedelta(minutes=5):
            return True
    return False

def update_session_activity():
    session['last_activity'] = datetime.now().isoformat()

def get_db():
    conn = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            wallet_address TEXT UNIQUE,
            balance_usd REAL DEFAULT 10000.0,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT (datetime('now')),
            last_login TIMESTAMP,
            is_verified BOOLEAN DEFAULT 0,
            is_active BOOLEAN DEFAULT 1
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            phone TEXT,
            address TEXT,
            encrypted_id TEXT,
            date_of_birth DATE,
            bio TEXT,
            updated_at TIMESTAMP DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS holdings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            crypto_symbol TEXT NOT NULL,
            amount REAL NOT NULL,
            purchase_price REAL NOT NULL,
            purchase_date TIMESTAMP DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            crypto_symbol TEXT NOT NULL,
            amount REAL NOT NULL,
            price_at_time REAL NOT NULL,
            total_usd REAL NOT NULL,
            encrypted_notes TEXT,
            timestamp TIMESTAMP DEFAULT (datetime('now')),
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            crypto_symbol TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, crypto_symbol)
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            crypto_symbol TEXT NOT NULL,
            target_price REAL NOT NULL,
            alert_type TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT (datetime('now'))
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            upload_date TIMESTAMP DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        
        conn.commit()

def simulate_price_change():
    for symbol in CRYPTO_PRICES:
        change = random.uniform(-0.02, 0.02)
        CRYPTO_PRICES[symbol] *= (1 + change)

# Before request
@app.before_request
def before_request():
    if request.endpoint not in ['login', 'register', 'static'] and 'user_id' in session:
        if check_session_timeout():
            user_id = session.get('user_id')
            log_audit(user_id, 'SESSION_TIMEOUT', 'Session expired due to inactivity', request.remote_addr)
            session.clear()
            flash('Session expired due to inactivity. Please login again.', 'warning')
            return redirect(url_for('login'))
        update_session_activity()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', ''))
            email = sanitize_input(request.form.get('email', ''))
            full_name = sanitize_input(request.form.get('full_name', ''))
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not username or len(username) < 3:
                flash('Username must be at least 3 characters long', 'error')
                return render_template('crypto_register.html')
            
            if len(username) > 50:
                flash('Username is too long (max 50 characters)', 'error')
                return render_template('crypto_register.html')
            
            if not validate_email(email):
                flash('Invalid email format', 'error')
                return render_template('crypto_register.html')
            
            is_valid, message = validate_password_strength(password)
            if not is_valid:
                flash(message, 'error')
                return render_template('crypto_register.html')
            
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('crypto_register.html')
            
            with get_db() as conn:
                c = conn.cursor()
                c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
                if c.fetchone():
                    flash('Username or email already exists', 'error')
                    return render_template('crypto_register.html')
                
                password_hash = generate_password_hash(password, method='scrypt')
                wallet_address = f"0x{secrets.token_hex(20)}"
                
                c.execute('''INSERT INTO users (username, email, password_hash, full_name, wallet_address)
                           VALUES (?, ?, ?, ?, ?)''',
                         (username, email, password_hash, full_name, wallet_address))
                user_id = c.lastrowid
                c.execute('INSERT INTO user_profiles (user_id) VALUES (?)', (user_id,))
                conn.commit()
                
                log_audit(user_id, 'USER_REGISTERED', f'New user registered: {username}', request.remote_addr)
                flash('Account created! You have $10,000 demo balance. Please login.', 'success')
                return redirect(url_for('login'))
                
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('crypto_register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', ''))
            password = request.form.get('password', '')
            
            if not username or not password:
                flash('Username and password are required', 'error')
                return render_template('crypto_login.html')
            
            with get_db() as conn:
                c = conn.cursor()
                c.execute('''SELECT id, username, password_hash, wallet_address, 
                           failed_login_attempts, locked_until, is_active
                           FROM users WHERE username = ?''', (username,))
                user = c.fetchone()
                
                if not user:
                    log_audit(None, 'LOGIN_FAILED', f'Failed login for non-existent user: {username}', request.remote_addr)
                    flash('Invalid username or password', 'error')
                    return render_template('crypto_login.html')
                
                user_id = user['id']
                password_hash = user['password_hash']
                failed_attempts = user['failed_login_attempts']
                locked_until = user['locked_until']
                
                if locked_until:
                    locked_until_dt = datetime.fromisoformat(locked_until)
                    if datetime.now() < locked_until_dt:
                        remaining = (locked_until_dt - datetime.now()).seconds // 60
                        flash(f'Account locked. Try again in {remaining} minutes.', 'error')
                        return render_template('crypto_login.html')
                    else:
                        c.execute('''UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE id = ?''', (user_id,))
                        conn.commit()
                        failed_attempts = 0
                
                if not user['is_active']:
                    flash('Account is deactivated. Contact support.', 'error')
                    return render_template('crypto_login.html')
                
                if check_password_hash(password_hash, password):
                    c.execute('''UPDATE users SET last_login = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?''', (datetime.now(), user_id))
                    conn.commit()
                    
                    session.clear()
                    session['user_id'] = user_id
                    session['username'] = user['username']
                    session['wallet_address'] = user['wallet_address']
                    update_session_activity()
                    
                    log_audit(user_id, 'LOGIN_SUCCESS', 'User logged in successfully', request.remote_addr)
                    flash('Welcome to CryptoTrader Pro!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    failed_attempts += 1
                    if failed_attempts >= 5:
                        locked_until = datetime.now() + timedelta(minutes=15)
                        c.execute('''UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?''',
                                 (failed_attempts, locked_until, user_id))
                        flash('Account locked due to 5 failed attempts. Try again in 15 minutes.', 'error')
                    else:
                        c.execute('''UPDATE users SET failed_login_attempts = ? WHERE id = ?''', (failed_attempts, user_id))
                        remaining = 5 - failed_attempts
                        flash(f'Invalid password. {remaining} attempts remaining.', 'error')
                    
                    conn.commit()
                    log_audit(user_id, 'LOGIN_FAILED', f'Failed login attempt {failed_attempts}', request.remote_addr)
                
        except Exception as e:
            logging.error(f"Login error: {str(e)}", exc_info=True)
            flash('Login failed. Please try again.', 'error')
    
    return render_template('crypto_login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        simulate_price_change()
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
            user = c.fetchone()
            
            c.execute('SELECT * FROM holdings WHERE user_id = ? ORDER BY amount * ? DESC',
                     (session['user_id'], CRYPTO_PRICES.get('BTC', 0)))
            holdings = c.fetchall()
            
            portfolio_value = user['balance_usd']
            for holding in holdings:
                current_price = CRYPTO_PRICES.get(holding['crypto_symbol'], 0)
                portfolio_value += holding['amount'] * current_price
            
            c.execute('SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC LIMIT 5',
                     (session['user_id'],))
            transactions = c.fetchall()
            
            c.execute('SELECT crypto_symbol FROM watchlist WHERE user_id = ?', (session['user_id'],))
            watchlist = [row['crypto_symbol'] for row in c.fetchall()]
            
            log_audit(session['user_id'], 'DASHBOARD_ACCESS', 'User accessed dashboard', request.remote_addr)
            
            return render_template('crypto_dashboard.html',
                                 user=user,
                                 holdings=holdings,
                                 portfolio_value=portfolio_value,
                                 transactions=transactions,
                                 watchlist=watchlist,
                                 prices=CRYPTO_PRICES,
                                 user_balance=user['balance_usd'])
    except Exception as e:
        logging.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/trade/<symbol>', methods=['GET', 'POST'])
def trade(symbol):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            action = sanitize_input(request.form.get('action', ''))
            amount_str = request.form.get('amount', '')
            notes = request.form.get('notes', '')
            
            if action not in ['buy', 'sell']:
                flash('Invalid action', 'error')
                return render_template('crypto_trade.html', symbol=symbol, price=CRYPTO_PRICES.get(symbol, 0))
            
            is_valid, amount = validate_numeric(amount_str, min_val=0.000001, max_val=100000)
            if not is_valid:
                flash(f'Invalid amount: {amount}', 'error')
                return render_template('crypto_trade.html', symbol=symbol, price=CRYPTO_PRICES.get(symbol, 0))
            
            encrypted_notes = encrypt_data(notes) if notes else ''
            current_price = CRYPTO_PRICES.get(symbol, 0)
            total_cost = amount * current_price
            
            with get_db() as conn:
                c = conn.cursor()
                c.execute('SELECT balance_usd FROM users WHERE id = ?', (session['user_id'],))
                balance = c.fetchone()['balance_usd']
                
                if action == 'buy':
                    if balance >= total_cost:
                        c.execute('UPDATE users SET balance_usd = balance_usd - ? WHERE id = ?', (total_cost, session['user_id']))
                        c.execute('''INSERT INTO holdings (user_id, crypto_symbol, amount, purchase_price)
                                   VALUES (?, ?, ?, ?)''', (session['user_id'], symbol, amount, current_price))
                        c.execute('''INSERT INTO transactions 
                                   (user_id, transaction_type, crypto_symbol, amount, price_at_time, 
                                    total_usd, encrypted_notes, ip_address)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                 (session['user_id'], 'BUY', symbol, amount, current_price, total_cost, encrypted_notes, request.remote_addr))
                        conn.commit()
                        log_audit(session['user_id'], 'TRADE_BUY', f'Bought {amount} {symbol}', request.remote_addr)
                        flash(f'Successfully bought {amount} {symbol}!', 'success')
                    else:
                        flash('Insufficient balance', 'error')
                
                elif action == 'sell':
                    c.execute('SELECT SUM(amount) as total FROM holdings WHERE user_id = ? AND crypto_symbol = ?', (session['user_id'], symbol))
                    holding = c.fetchone()
                    if holding and holding['total'] >= amount:
                        c.execute('UPDATE users SET balance_usd = balance_usd + ? WHERE id = ?', (total_cost, session['user_id']))
                        c.execute('''UPDATE holdings SET amount = amount - ? WHERE user_id = ? AND crypto_symbol = ? AND amount > 0''',
                                 (amount, session['user_id'], symbol))
                        c.execute('DELETE FROM holdings WHERE amount <= 0')
                        c.execute('''INSERT INTO transactions 
                                   (user_id, transaction_type, crypto_symbol, amount, price_at_time, 
                                    total_usd, encrypted_notes, ip_address)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                 (session['user_id'], 'SELL', symbol, amount, current_price, total_cost, encrypted_notes, request.remote_addr))
                        conn.commit()
                        log_audit(session['user_id'], 'TRADE_SELL', f'Sold {amount} {symbol}', request.remote_addr)
                        flash(f'Successfully sold {amount} {symbol}!', 'success')
                    else:
                        flash('Insufficient holdings', 'error')
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logging.error(f"Trade error: {str(e)}")
            flash('Trade failed.', 'error')
    
    return render_template('crypto_trade.html', symbol=symbol, price=CRYPTO_PRICES.get(symbol, 0), user_balance=0)

@app.route('/markets')
def markets():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    simulate_price_change()
    log_audit(session['user_id'], 'MARKETS_VIEWED', 'User viewed markets', request.remote_addr)
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT balance_usd FROM users WHERE id = ?', (session['user_id'],))
        balance = c.fetchone()['balance_usd']
    
    return render_template('crypto_markets.html', prices=CRYPTO_PRICES, user_balance=balance)

@app.route('/portfolio')
def portfolio():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
            user = c.fetchone()
            c.execute('SELECT * FROM holdings WHERE user_id = ?', (session['user_id'],))
            holdings = c.fetchall()
            c.execute('SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC', (session['user_id'],))
            transactions = c.fetchall()
            log_audit(session['user_id'], 'PORTFOLIO_VIEWED', 'User viewed portfolio', request.remote_addr)
            return render_template('crypto_portfolio.html',
                                 user=user, holdings=holdings, transactions=transactions,
                                 prices=CRYPTO_PRICES, user_balance=user['balance_usd'])
    except Exception as e:
        logging.error(f"Portfolio error: {str(e)}")
        flash('Error loading portfolio', 'error')
        return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            phone = sanitize_input(request.form.get('phone', ''))
            address = sanitize_input(request.form.get('address', ''))
            government_id = request.form.get('government_id', '')
            dob = request.form.get('date_of_birth', '')
            bio = sanitize_input(request.form.get('bio', ''))
            
            if phone and not re.match(r'^\+?[\d\s\-\(\)]{10,15}$', phone):
                flash('Invalid phone number format', 'error')
                return redirect(url_for('profile'))
            
            if address:
                is_valid, address = validate_input_length(address, 200)
                if not is_valid:
                    flash(address, 'error')
                    return redirect(url_for('profile'))
            
            if bio:
                is_valid, bio = validate_input_length(bio, 500)
                if not is_valid:
                    flash(bio, 'error')
                    return redirect(url_for('profile'))
            
            encrypted_id = encrypt_data(government_id) if government_id else None
            
            with get_db() as conn:
                c = conn.cursor()
                if encrypted_id:
                    c.execute('''UPDATE user_profiles SET phone = ?, address = ?, encrypted_id = ?, 
                               date_of_birth = ?, bio = ?, updated_at = ? WHERE user_id = ?''',
                             (phone, address, encrypted_id, dob, bio, datetime.now(), session['user_id']))
                else:
                    c.execute('''UPDATE user_profiles SET phone = ?, address = ?, date_of_birth = ?, 
                               bio = ?, updated_at = ? WHERE user_id = ?''',
                             (phone, address, dob, bio, datetime.now(), session['user_id']))
                conn.commit()
                log_audit(session['user_id'], 'PROFILE_UPDATED', 'User profile updated', request.remote_addr)
                flash('Profile updated successfully!', 'success')
                
        except Exception as e:
            logging.error(f"Profile update error: {str(e)}")
            flash('Profile update failed.', 'error')
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''SELECT u.username, u.full_name, u.email, u.wallet_address, u.balance_usd, 
                               p.phone, p.address, p.encrypted_id, p.date_of_birth, p.bio
                       FROM users u LEFT JOIN user_profiles p ON u.id = p.user_id WHERE u.id = ?''', (session['user_id'],))
            user_data = c.fetchone()
            gov_id = decrypt_data(user_data['encrypted_id']) if user_data and user_data['encrypted_id'] else ''
            masked_id = 'XXXX-XXXX-' + gov_id[-4:] if gov_id and len(gov_id) >= 4 else ''
            log_audit(session['user_id'], 'PROFILE_VIEWED', 'User viewed profile', request.remote_addr)
            return render_template('crypto_profile.html', user=user_data, masked_id=masked_id, user_balance=user_data['balance_usd'])
    except Exception as e:
        logging.error(f"Profile load error: {str(e)}")
        return render_template('crypto_profile.html', user_balance=0)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file selected', 'error')
                return render_template('crypto_upload.html', user_balance=0)
            
            file = request.files['file']
            if file.filename == '':
                flash('No file selected', 'error')
                return render_template('crypto_upload.html', user_balance=0)
            
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = timestamp + filename
                
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                
                if file_size > app.config['MAX_CONTENT_LENGTH']:
                    flash('File too large (max 5MB)', 'error')
                    return render_template('crypto_upload.html', user_balance=0)
                
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                with get_db() as conn:
                    c = conn.cursor()
                    c.execute('''INSERT INTO uploaded_files (user_id, filename, file_size) VALUES (?, ?, ?)''',
                             (session['user_id'], filename, file_size))
                    conn.commit()
                
                log_audit(session['user_id'], 'FILE_UPLOADED', f'File uploaded: {filename}', request.remote_addr)
                flash(f'File {filename} uploaded successfully!', 'success')
            else:
                flash('Invalid file type.', 'error')
                
        except Exception as e:
            logging.error(f"File upload error: {str(e)}")
            flash('Upload failed.', 'error')
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT balance_usd FROM users WHERE id = ?', (session['user_id'],))
        balance = c.fetchone()['balance_usd']
    return render_template('crypto_upload.html', user_balance=balance)

@app.route('/audit')
def audit_logs():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            
            # Get filter parameters
            filter_action = request.args.get('filter', 'all')
            date_from = request.args.get('date_from', '')
            date_to = request.args.get('date_to', '')
            
            # Build query based on filters
            query = '''SELECT action, details, ip_address, timestamp FROM audit_logs 
                       WHERE user_id = ?'''
            params = [session['user_id']]
            
            if filter_action != 'all':
                query += ' AND action LIKE ?'
                params.append(f'%{filter_action}%')
            
            if date_from:
                query += ' AND DATE(timestamp) >= ?'
                params.append(date_from)
            
            if date_to:
                query += ' AND DATE(timestamp) <= ?'
                params.append(date_to)
            
            query += ' ORDER BY timestamp DESC LIMIT 100'
            
            c.execute(query, params)
            logs = c.fetchall()
            
            # Get activity statistics
            c.execute('''SELECT 
                           COUNT(*) as total_activities,
                           COUNT(DISTINCT DATE(timestamp)) as active_days,
                           COUNT(CASE WHEN action LIKE '%LOGIN%' THEN 1 END) as login_count,
                           COUNT(CASE WHEN action LIKE '%TRADE%' THEN 1 END) as trade_count,
                           COUNT(CASE WHEN action LIKE '%PROFILE%' THEN 1 END) as profile_count,
                           MIN(timestamp) as first_activity,
                           MAX(timestamp) as last_activity
                       FROM audit_logs WHERE user_id = ?''', (session['user_id'],))
            stats = c.fetchone()
            
            # Get activity by day (last 7 days)
            c.execute('''SELECT DATE(timestamp) as activity_date, COUNT(*) as count
                       FROM audit_logs 
                       WHERE user_id = ? AND DATE(timestamp) >= DATE('now', '-7 days')
                       GROUP BY DATE(timestamp)
                       ORDER BY DATE(timestamp) DESC''', (session['user_id'],))
            daily_activity = c.fetchall()
            
            # Get most common actions
            c.execute('''SELECT action, COUNT(*) as count
                       FROM audit_logs 
                       WHERE user_id = ?
                       GROUP BY action
                       ORDER BY count DESC
                       LIMIT 5''', (session['user_id'],))
            top_actions = c.fetchall()
            
            c.execute('SELECT balance_usd FROM users WHERE id = ?', (session['user_id'],))
            balance = c.fetchone()['balance_usd']
            
            log_audit(session['user_id'], 'AUDIT_ACCESSED', 'User viewed activity logs', request.remote_addr)
            
            return render_template('crypto_audit.html', 
                                 logs=logs, 
                                 user_balance=balance,
                                 stats=stats,
                                 daily_activity=daily_activity,
                                 top_actions=top_actions,
                                 filter_action=filter_action,
                                 date_from=date_from,
                                 date_to=date_to)
    except Exception as e:
        logging.error(f"Audit view error: {str(e)}")
        flash('Error loading activity logs', 'error')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_audit(user_id, 'LOGOUT', 'User logged out', request.remote_addr)
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('crypto_error.html', error_code=404, error_message="Page not found", user_balance=0), 404

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal server error: {str(error)}")
    return render_template('crypto_error.html', error_code=500, error_message="Internal server error", user_balance=0), 500

@app.errorhandler(413)
def file_too_large(error):
    flash('File too large. Maximum size is 5MB.', 'error')
    return redirect(url_for('upload_file'))

# Create templates
def create_templates():
    os.makedirs('templates', exist_ok=True)
    
    templates = {
        'crypto_base.html': r'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}CryptoTrader Pro{% endblock %}</title>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        :root {
            --bg: #0a0e17;
            --card-bg: rgba(15, 20, 35, 0.7);
            --glass: rgba(30, 40, 70, 0.4);
            --primary: #6e56cf;
            --accent: #00d9ff;
            --gold: #ffd700;
            --danger: #ff4d6d;
            --success: #00ff88;
            --text: #e0e7ff;
            --text-muted: #94a3b8;
            --border: rgba(110, 86, 207, 0.3);
            --shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Space Grotesk', sans-serif;
            background: linear-gradient(135deg, #0a0e17 0%, #1a1f2e 100%);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }

        .bg-anim {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: 
                radial-gradient(circle at 20% 80%, rgba(110, 86, 207, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(0, 217, 255, 0.15) 0%, transparent 50%);
            z-index: -1;
            animation: pulse 8s infinite alternate;
        }
        @keyframes pulse {
            0% { opacity: 0.7; }
            100% { opacity: 1; }
        }

        .glass-card {
            background: var(--glass);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            transition: var(--transition);
        }
        .glass-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 16px 40px rgba(110, 86, 207, 0.2);
        }

        /* Auth Container - Centered */
        .auth-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }

        .app-container {
            display: flex;
            min-height: 100vh;
        }
        .main-content {
            flex: 1;
            padding: 1.5rem;
            margin-left: 0;
            margin-right: 280px;
            transition: margin-right 0.4s ease;
        }
        .main-content.collapsed {
            margin-right: 0;
        }
        
        /* No margin for auth pages */
        .main-content.no-sidebar {
            margin-right: 0;
        }

        .navbar {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 70px;
            background: rgba(10, 14, 23, 0.8);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border);
            z-index: 1000;
            display: flex;
            align-items: center;
            padding: 0 1.5rem;
            justify-content: space-between;
        }
        .logo {
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 1.6rem;
            color: var(--accent);
            letter-spacing: 1px;
        }
        .nav-actions {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        .nav-btn {
            background: transparent;
            border: 1px solid var(--primary);
            color: var(--text);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: var(--transition);
            text-decoration: none;
        }
        .nav-btn:hover {
            background: var(--primary);
            color: white;
            transform: translateY(-2px);
        }

        .sidebar {
            position: fixed;
            right: 0;
            top: 70px;
            width: 280px;
            height: calc(100vh - 70px);
            background: rgba(15, 20, 35, 0.9);
            backdrop-filter: blur(12px);
            border-left: 1px solid var(--border);
            padding: 1.5rem;
            transition: transform 0.4s ease;
            z-index: 900;
        }
        .sidebar.collapsed {
            transform: translateX(100%);
        }
        .sidebar-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }
        .sidebar-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--accent);
        }
        .toggle-sidebar {
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 1.3rem;
            cursor: pointer;
        }

        .user-info {
            background: var(--glass);
            border-radius: 12px;
            padding: 1rem;
            margin-bottom: 1.5rem;
            text-align: center;
            border: 1px solid var(--border);
        }
        .user-avatar {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border-radius: 50%;
            margin: 0 auto 0.75rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: white;
            font-weight: bold;
        }
        .user-name {
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        .user-balance {
            font-family: 'JetBrains Mono', monospace;
            color: var(--gold);
            font-weight: 700;
            font-size: 1.1rem;
        }

        .quick-actions {
            margin-top: 1.5rem;
        }
        .action-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem;
            border-radius: 8px;
            color: var(--text);
            text-decoration: none;
            transition: var(--transition);
            margin-bottom: 0.5rem;
        }
        .action-item:hover {
            background: rgba(110, 86, 207, 0.2);
            color: var(--accent);
        }
        .action-icon {
            width: 36px;
            height: 36px;
            background: var(--glass);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
            color: var(--accent);
        }

        .page-header {
            margin-bottom: 2rem;
            text-align: center;
        }
        .page-title {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }
        .page-subtitle {
            color: var(--text-muted);
            font-size: 1rem;
        }

        .form-group {
            margin-bottom: 1.25rem;
        }
        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--accent);
            font-size: 0.95rem;
        }
        .form-input, .form-select, .form-textarea {
            width: 100%;
            padding: 0.75rem 1rem;
            background: rgba(20, 25, 40, 0.6);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-family: inherit;
            transition: var(--transition);
        }
        .form-input:focus, .form-select:focus, .form-textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(110, 86, 207, 0.2);
        }

        /* Password input wrapper */
        .password-wrapper {
            position: relative;
            display: flex;
            align-items: center;
        }
        .password-wrapper input {
            padding-right: 3rem;
        }
        .password-toggle {
            position: absolute;
            right: 12px;
            background: none;
            border: none;
            color: var(--accent);
            cursor: pointer;
            font-size: 1.1rem;
            padding: 0.5rem;
            transition: var(--transition);
        }
        .password-toggle:hover {
            color: var(--primary);
            transform: scale(1.1);
        }

        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            font-size: 0.95rem;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            text-decoration: none;
        }
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), #8a70e0);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(110, 86, 207, 0.4);
        }
        .btn-secondary {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text);
        }
        .btn-secondary:hover {
            background: rgba(110, 86, 207, 0.2);
            border-color: var(--primary);
        }

        .alert {
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { transform: translateY(-20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .alert-success { background: rgba(0, 255, 136, 0.1); border-left: 4px solid var(--success); color: var(--success); }
        .alert-error { background: rgba(255, 77, 109, 0.1); border-left: 4px solid var(--danger); color: var,--danger); }
        .alert-info { background: rgba(0, 217, 255, 0.1); border-left: 4px solid var(--accent); color: var(--accent); }
        .alert-warning { background: rgba(255, 215, 0, 0.1); border-left: 4px solid var(--gold); color: var(--gold); }

        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        .data-table th {
            text-align: left;
            padding: 1rem;
            background: rgba(110, 86, 207, 0.2);
            color: var(--accent);
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .data-table td {
            padding: 1rem;
            border-bottom: 1px solid var(--border);
        }
        .data-table tr:hover td {
            background: rgba(110, 86, 207, 0.1);
        }

        @media (max-width: 992px) {
            .sidebar { transform: translateX(100%); }
            .main-content { margin-right: 0 !important; }
            .navbar { padding: 0 1rem; }
        }

        .sidebar-toggle {
            display: none;
            background: var(--primary);
            color: white;
            border: none;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            cursor: pointer;
            font-size: 1.2rem;
            position: fixed;
            right: 20px;
            bottom: 20px;
            z-index: 1001;
            box-shadow: 0 4px 15px rgba(110, 86, 207, 0.4);
        }
        @media (max-width: 992px) {
            .sidebar-toggle { display: block; }
        }
    </style>
</head>
<body>
    <div class="bg-anim"></div>

    <nav class="navbar">
        <div class="logo"><i class="fas fa-chart-line"></i> CRYPTO PRO</div>
        <div class="nav-actions">
            {% if session.user_id %}
            <button class="nav-btn" onclick="toggleSidebar()">
                <i class="fas fa-user"></i> {{ session.username }}
            </button>
            <a href="{{ url_for('logout') }}" class="nav-btn">
                <i class="fas fa-sign-out-alt"></i> Logout
            </a>
            {% else %}
            <a href="{{ url_for('login') }}" class="nav-btn">
                <i class="fas fa-sign-in-alt"></i> Login
            </a>
            <a href="{{ url_for('register') }}" class="nav-btn">
                <i class="fas fa-user-plus"></i> Register
            </a>
            {% endif %}
        </div>
    </nav>

    <div class="app-container">
        <main class="main-content {% if not session.user_id %}no-sidebar{% endif %}" id="mainContent" style="margin-top: 70px;">
            <div class="container" style="max-width: 1200px; margin: 0 auto;">
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">
                                <i class="fas fa-{{ 'check-circle' if category == 'success' else 'exclamation-triangle' if category == 'warning' else 'times-circle' if category == 'error' else 'info-circle' }}"></i>
                                {{ message }}
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                {% block content %}{% endblock %}
            </div>
        </main>

        {% if session.user_id %}
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-title"><i class="fas fa-bolt"></i> TRADER HUB</div>
                <button class="toggle-sidebar" onclick="toggleSidebar()"><i class="fas fa-times"></i></button>
            </div>

            <div class="user-info">
                <div class="user-avatar">{{ session.username[0].upper() }}</div>
                <div class="user-name">{{ session.username }}</div>
                <div class="user-balance">${{ "%.2f"|format(user_balance) }}</div>
            </div>

            <div class="quick-actions">
                <a href="{{ url_for('dashboard') }}" class="action-item">
                    <div class="action-icon"><i class="fas fa-home"></i></div>
                    <div>Dashboard</div>
                </a>
                <a href="{{ url_for('markets') }}" class="action-item">
                    <div class="action-icon"><i class="fas fa-chart-bar"></i></div>
                    <div>Markets</div>
                </a>
                <a href="{{ url_for('portfolio') }}" class="action-item">
                    <div class="action-icon"><i class="fas fa-briefcase"></i></div>
                    <div>Portfolio</div>
                </a>
                <a href="{{ url_for('profile') }}" class="action-item">
                    <div class="action-icon"><i class="fas fa-user-circle"></i></div>
                    <div>Profile</div>
                </a>
                <a href="{{ url_for('upload_file') }}" class="action-item">
                    <div class="action-icon"><i class="fas fa-upload"></i></div>
                    <div>Upload</div>
                </a>
                <a href="{{ url_for('audit_logs') }}" class="action-item">
                    <div class="action-icon"><i class="fas fa-shield-alt"></i></div>
                    <div>Audit</div>
                </a>
            </div>
        </aside>
        {% endif %}
    </div>

    <button class="sidebar-toggle" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>

    <script>
        function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            const mainContent = document.getElementById('mainContent');
            if (sidebar) {
                sidebar.classList.toggle('collapsed');
                mainContent.classList.toggle('collapsed');
            }
        }
        
        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const icon = input.nextElementSibling.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        }
        
        setTimeout(() => {
            document.querySelectorAll('.alert').forEach(alert => {
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-20px)';
                setTimeout(() => alert.remove(), 300);
            });
        }, 4000);
    </script>
</body>
</html>''',

        'crypto_login.html': r'''{% extends "crypto_base.html" %}
{% block title %}Login - CryptoTrader Pro{% endblock %}
{% block content %}
<div class="auth-container">
    <div class="glass-card" style="max-width: 450px; width: 100%; text-align: center; padding: 2.5rem;">
        <div style="margin-bottom: 2rem;">
            <i class="fas fa-chart-line" style="font-size: 3rem; color: var(--accent); margin-bottom: 1rem;"></i>
            <h1 style="font-size: 2rem; margin-bottom: 0.5rem; background: linear-gradient(135deg, var(--primary), var(--accent)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                TRADER LOGIN
            </h1>
            <p style="color: var(--text-muted); font-size: 0.95rem;">Access your crypto trading dashboard</p>
        </div>
        
        <form method="POST">
            <div class="form-group" style="text-align: left;">
                <label class="form-label">Username</label>
                <input type="text" name="username" class="form-input" required placeholder="Enter your username" autocomplete="username">
            </div>
            
            <div class="form-group" style="text-align: left;">
                <label class="form-label">Password</label>
                <div class="password-wrapper">
                    <input type="password" id="loginPass" name="password" class="form-input" required placeholder="Enter your password" autocomplete="current-password">
                    <button type="button" class="password-toggle" onclick="togglePassword('loginPass')">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
            
            <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 1rem;">
                <i class="fas fa-rocket"></i> ENTER PLATFORM
            </button>
        </form>
        
        <div style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border);">
            <p style="color: var(--text-muted);">
                New trader? <a href="{{ url_for('register') }}" style="color: var(--accent); text-decoration: none; font-weight: 600;">Create Account</a>
            </p>
        </div>
    </div>
</div>
{% endblock %}''',

        'crypto_register.html': r'''{% extends "crypto_base.html" %}
{% block title %}Register - CryptoTrader Pro{% endblock %}
{% block content %}
<div class="auth-container">
    <div class="glass-card" style="max-width: 550px; width: 100%; padding: 2.5rem;">
        <div style="text-align: center; margin-bottom: 2rem;">
            <i class="fas fa-user-plus" style="font-size: 3rem; color: var(--accent); margin-bottom: 1rem;"></i>
            <h1 style="font-size: 2rem; margin-bottom: 0.5rem; background: linear-gradient(135deg, var(--primary), var(--accent)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                CREATE ACCOUNT
            </h1>
            <p style="color: var(--text-muted); font-size: 0.95rem;">Join the crypto trading revolution</p>
        </div>
        
        <form method="POST">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                <div class="form-group">
                    <label class="form-label">Username *</label>
                    <input type="text" name="username" class="form-input" required minlength="3" maxlength="50" placeholder="johndoe" autocomplete="username">
                    <small style="color: var(--text-muted); font-size: 0.8rem;">3-50 characters</small>
                </div>
                <div class="form-group">
                    <label class="form-label">Full Name *</label>
                    <input type="text" name="full_name" class="form-input" required placeholder="John Doe" autocomplete="name">
                </div>
            </div>
            
            <div class="form-group">
                <label class="form-label">Email *</label>
                <input type="email" name="email" class="form-input" required placeholder="john@example.com" autocomplete="email">
            </div>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                <div class="form-group">
                    <label class="form-label">Password *</label>
                    <div class="password-wrapper">
                        <input type="password" id="regPass" name="password" class="form-input" required placeholder="••••••••" autocomplete="new-password">
                        <button type="button" class="password-toggle" onclick="togglePassword('regPass')">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <small style="color: var(--text-muted); font-size: 0.8rem;">Min 8 chars, upper, lower, digit, special</small>
                </div>
                <div class="form-group">
                    <label class="form-label">Confirm Password *</label>
                    <div class="password-wrapper">
                        <input type="password" id="confirmPass" name="confirm_password" class="form-input" required placeholder="••••••••" autocomplete="new-password">
                        <button type="button" class="password-toggle" onclick="togglePassword('confirmPass')">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="glass-card" style="background: rgba(110, 86, 207, 0.1); margin: 1rem 0; padding: 1rem;">
                <p style="color: var(--accent); font-weight: 600; margin-bottom: 0.5rem;">
                    <i class="fas fa-shield-check"></i> Security Requirements:
                </p>
                <ul style="margin-left: 1.5rem; color: var(--text-muted); font-size: 0.85rem; line-height: 1.6;">
                    <li>Minimum 8 characters</li>
                    <li>One uppercase & lowercase letter</li>
                    <li>One digit & special character</li>
                </ul>
            </div>
            
            <button type="submit" class="btn btn-primary" style="width: 100%;">
                <i class="fas fa-rocket"></i> START TRADING
            </button>
        </form>
        
        <div style="text-align: center; margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border);">
            <p style="color: var(--text-muted);">
                Already have account? <a href="{{ url_for('login') }}" style="color: var(--accent); text-decoration: none; font-weight: 600;">Login</a>
            </p>
        </div>
    </div>
</div>
{% endblock %}''',

        'crypto_dashboard.html': r'''{% extends "crypto_base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<div class="page-header">
    <h1 class="page-title">TRADING DASHBOARD</h1>
</div>

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem;">
    <div class="glass-card" style="text-align: center;">
        <div style="font-size: 2rem; font-weight: 700; color: var(--gold);">${{ "%.2f"|format(portfolio_value) }}</div>
        <div style="color: var(--text-muted);">Total Portfolio</div>
    </div>
    <div class="glass-card" style="text-align: center;">
        <div style="font-size: 2rem; font-weight: 700; color: var(--success);">${{ "%.2f"|format(user.balance_usd) }}</div>
        <div style="color: var(--text-muted);">USD Balance</div>
    </div>
    <div class="glass-card" style="text-align: center;">
        <div style="font-size: 2rem; font-weight: 700; color: var(--accent);">{{ holdings|length }}</div>
        <div style="color: var(--text-muted);">Assets Held</div>
    </div>
</div>

<div class="glass-card">
    <h2 style="color: var(--accent); margin-bottom: 1rem;">YOUR HOLDINGS</h2>
    {% if holdings %}
    <table class="data-table">
        <thead>
            <tr><th>Asset</th><th>Amount</th><th>Price</th><th>Value</th><th>P/L</th><th>Action</th></tr>
        </thead>
        <tbody>
            {% for h in holdings %}
            <tr>
                <td style="font-weight: 700;">{{ h.crypto_symbol }}</td>
                <td>{{ "%.6f"|format(h.amount) }}</td>
                <td style="color: var(--success);">${{ "%.2f"|format(prices[h.crypto_symbol]) }}</td>
                <td>${{ "%.2f"|format(h.amount * prices[h.crypto_symbol]) }}</td>
                <td style="color: {{ 'var(--success)' if prices[h.crypto_symbol] > h.purchase_price else 'var(--danger)' }};">
                    {{ "%.1f"|format(((prices[h.crypto_symbol] - h.purchase_price) / h.purchase_price) * 100) }}%
                </td>
                <td><a href="{{ url_for('trade', symbol=h.crypto_symbol) }}" class="btn btn-primary" style="padding: 0.5rem 1rem; font-size: 0.8rem;">TRADE</a></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p style="text-align: center; padding: 2rem; color: var(--text-muted);">No holdings yet.</p>
    {% endif %}
</div>
{% endblock %}''',

        'crypto_trade.html': r'''{% extends "crypto_base.html" %}
{% block title %}Trade {{ symbol }}{% endblock %}
{% block content %}
<div style="max-width: 600px; margin: 0 auto;">
    <div class="page-header">
        <h1 class="page-title">TRADE {{ symbol }}</h1>
    </div>
    <div class="glass-card" style="text-align: center; margin-bottom: 2rem;">
        <div style="font-size: 3rem; color: var(--success); font-weight: 700;">${{ "%.2f"|format(price) }}</div>
    </div>
    <div class="glass-card">
        <form method="POST">
            <div class="form-group">
                <label class="form-label">Action</label>
                <select name="action" class="form-select" required>
                    <option value="buy">BUY {{ symbol }}</option>
                    <option value="sell">SELL {{ symbol }}</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Amount</label>
                <input type="number" name="amount" step="0.000001" min="0.000001" class="form-input" required placeholder="0.000000">
            </div>
            <div class="form-group">
                <label class="form-label">Notes (Encrypted)</label>
                <textarea name="notes" class="form-textarea" rows="2" placeholder="Optional"></textarea>
            </div>
            <button type="submit" class="btn btn-primary" style="width: 100%;">EXECUTE TRADE</button>
        </form>
    </div>
</div>
{% endblock %}''',

        'crypto_markets.html': r'''{% extends "crypto_base.html" %}
{% block title %}Markets{% endblock %}
{% block content %}
<div class="page-header">
    <h1 class="page-title">CRYPTO MARKETS</h1>
</div>
<div class="glass-card">
    <table class="data-table">
        <thead>
            <tr><th>Asset</th><th>Price</th><th>24h</th><th>Action</th></tr>
        </thead>
        <tbody>
            {% for symbol, price in prices.items() %}
            <tr>
                <td style="font-weight: 700; color: var(--gold);">{{ symbol }}</td>
                <td style="color: var(--success);">${{ "%.2f"|format(price) }}</td>
                <td style="color: {{ 'var(--success)' if loop.index % 2 == 0 else 'var(--danger)' }};">
                    {{ '+' if loop.index % 2 == 0 else '-' }}{{ (loop.index * 1.5)|round(1) }}%
                </td>
                <td><a href="{{ url_for('trade', symbol=symbol) }}" class="btn btn-primary" style="padding: 0.5rem 1rem; font-size: 0.8rem;">TRADE</a></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}''',

        'crypto_portfolio.html': r'''{% extends "crypto_base.html" %}
{% block title %}Portfolio{% endblock %}
{% block content %}
<div class="page-header">
    <h1 class="page-title">MY PORTFOLIO</h1>
</div>
<div class="glass-card">
    <h2 style="color: var(--accent); margin-bottom: 1rem;">HOLDINGS</h2>
    {% if holdings %}
    <table class="data-table">
        <thead>
            <tr><th>Asset</th><th>Amount</th><th>Value</th><th>P/L</th></tr>
        </thead>
        <tbody>
            {% for h in holdings %}
            <tr>
                <td style="font-weight: 700;">{{ h.crypto_symbol }}</td>
                <td>{{ "%.6f"|format(h.amount) }}</td>
                <td>${{ "%.2f"|format(h.amount * prices[h.crypto_symbol]) }}</td>
                <td style="color: {{ 'var(--success)' if prices[h.crypto_symbol] > h.purchase_price else 'var(--danger)' }};">
                    {{ "%.1f"|format(((prices[h.crypto_symbol] - h.purchase_price) / h.purchase_price) * 100) }}%
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p style="text-align: center; padding: 2rem; color: var(--text-muted);">No holdings.</p>
    {% endif %}
</div>
{% endblock %}''',

        'crypto_profile.html': r'''{% extends "crypto_base.html" %}
{% block title %}Profile{% endblock %}
{% block content %}
<div class="page-header">
    <h1 class="page-title">TRADER PROFILE</h1>
</div>
<div class="glass-card">
    <form method="POST">
        <div class="form-group">
            <label class="form-label">Phone</label>
            <input type="tel" name="phone" value="{{ user.phone or '' }}" class="form-input">
        </div>
        <div class="form-group">
            <label class="form-label">Address</label>
            <textarea name="address" class="form-textarea" rows="2">{{ user.address or '' }}</textarea>
        </div>
        <div class="form-group">
            <label class="form-label">Gov ID (Encrypted)</label>
            <input type="password" name="government_id" class="form-input" placeholder="Update ID">
            {% if masked_id %}<small style="color: var(--success);">Current: {{ masked_id }}</small>{% endif %}
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">UPDATE PROFILE</button>
    </form>
</div>
{% endblock %}''',

        'crypto_upload.html': r'''{% extends "crypto_base.html" %}
{% block title %}Upload{% endblock %}
{% block content %}
<div class="page-header">
    <h1 class="page-title">FILE UPLOAD</h1>
</div>
<div class="glass-card">
    <form method="POST" enctype="multipart/form-data">
        <div class="form-group">
            <label class="form-label">Document</label>
            <input type="file" name="file" class="form-input" accept=".pdf,.jpg,.jpeg,.png" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">UPLOAD</button>
    </form>
</div>
{% endblock %}''',

        'crypto_audit.html': r'''{% extends "crypto_base.html" %}
{% block title %}Activity Logs - CryptoTrader Pro{% endblock %}
{% block content %}
<div class="page-header">
    <h1 class="page-title">ACTIVITY LOGS</h1>
    <p class="page-subtitle">Track all your platform activities</p>
</div>

<!-- Activity Statistics -->
<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2rem;">
    <div class="glass-card" style="text-align: center;">
        <div style="font-size: 2rem; font-weight: 700; color: var(--accent);">{{ stats[0] }}</div>
        <div style="color: var(--text-muted); font-size: 0.9rem;">Total Activities</div>
    </div>
    <div class="glass-card" style="text-align: center;">
        <div style="font-size: 2rem; font-weight: 700; color: var(--success);">{{ stats[1] }}</div>
        <div style="color: var(--text-muted); font-size: 0.9rem;">Active Days</div>
    </div>
    <div class="glass-card" style="text-align: center;">
        <div style="font-size: 2rem; font-weight: 700; color: var(--gold);">{{ stats[3] }}</div>
        <div style="color: var(--text-muted); font-size: 0.9rem;">Total Trades</div>
    </div>
    <div class="glass-card" style="text-align: center;">
        <div style="font-size: 2rem; font-weight: 700; color: var(--primary);">{{ stats[2] }}</div>
        <div style="color: var(--text-muted); font-size: 0.9rem;">Logins</div>
    </div>
</div>

<!-- Activity Timeline Chart -->
<div class="glass-card" style="margin-bottom: 2rem;">
    <h3 style="color: var(--accent); margin-bottom: 1rem;"><i class="fas fa-chart-line"></i> Last 7 Days Activity</h3>
    <div style="display: flex; gap: 0.5rem; align-items: flex-end; height: 150px;">
        {% for activity in daily_activity %}
        <div style="flex: 1; display: flex; flex-direction: column; align-items: center;">
            <div style="background: linear-gradient(to top, var(--primary), var(--accent)); 
                        width: 100%; 
                        height: {{ (activity[1] / stats[0] * 100)|int }}%; 
                        border-radius: 4px 4px 0 0;
                        transition: var(--transition);
                        position: relative;"
                 onmouseover="this.style.opacity='1'; this.querySelector('.tooltip').style.display='block';"
                 onmouseout="this.style.opacity='0.8'; this.querySelector('.tooltip').style.display='none';"
                 style="opacity: 0.8;">
                <div class="tooltip" style="display: none; position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); 
                                           background: var(--card-bg); padding: 0.5rem; border-radius: 4px; white-space: nowrap;
                                           border: 1px solid var(--border); margin-bottom: 5px;">
                    {{ activity[1] }} activities
                </div>
            </div>
            <small style="margin-top: 0.5rem; color: var(--text-muted);">{{ activity[0][-5:] }}</small>
        </div>
        {% endfor %}
    </div>
</div>

<!-- Top Actions -->
<div class="glass-card" style="margin-bottom: 2rem;">
    <h3 style="color: var(--accent); margin-bottom: 1rem;"><i class="fas fa-trophy"></i> Most Common Actions</h3>
    <div style="display: grid; gap: 0.75rem;">
        {% for action in top_actions %}
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem; 
                    background: rgba(110, 86, 207, 0.1); border-radius: 8px; border-left: 3px solid var(--primary);">
            <span style="font-weight: 600;">{{ action[0] }}</span>
            <span style="color: var(--success); font-weight: 700;">{{ action[1] }} times</span>
        </div>
        {% endfor %}
    </div>
</div>

<!-- Filters -->
<div class="glass-card" style="margin-bottom: 2rem;">
    <h3 style="color: var(--accent); margin-bottom: 1rem;"><i class="fas fa-filter"></i> Filter Activities</h3>
    <form method="GET" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
        <div class="form-group" style="margin-bottom: 0;">
            <label class="form-label" style="font-size: 0.85rem;">Action Type</label>
            <select name="filter" class="form-select" onchange="this.form.submit()">
                <option value="all" {% if filter_action == 'all' %}selected{% endif %}>All Activities</option>
                <option value="LOGIN" {% if filter_action == 'LOGIN' %}selected{% endif %}>Logins</option>
                <option value="TRADE" {% if filter_action == 'TRADE' %}selected{% endif %}>Trades</option>
                <option value="PROFILE" {% if filter_action == 'PROFILE' %}selected{% endif %}>Profile Updates</option>
                <option value="DASHBOARD" {% if filter_action == 'DASHBOARD' %}selected{% endif %}>Dashboard Views</option>
                <option value="MARKETS" {% if filter_action == 'MARKETS' %}selected{% endif %}>Market Views</option>
                <option value="FILE" {% if filter_action == 'FILE' %}selected{% endif %}>File Uploads</option>
            </select>
        </div>
        <div class="form-group" style="margin-bottom: 0;">
            <label class="form-label" style="font-size: 0.85rem;">From Date</label>
            <input type="date" name="date_from" value="{{ date_from }}" class="form-input" onchange="this.form.submit()">
        </div>
        <div class="form-group" style="margin-bottom: 0;">
            <label class="form-label" style="font-size: 0.85rem;">To Date</label>
            <input type="date" name="date_to" value="{{ date_to }}" class="form-input" onchange="this.form.submit()">
        </div>
        <div style="display: flex; align-items: flex-end;">
            <a href="{{ url_for('audit_logs') }}" class="btn btn-secondary" style="width: 100%;">
                <i class="fas fa-redo"></i> Reset
            </a>
        </div>
    </form>
</div>

<!-- Activity Log Table -->
<div class="glass-card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
        <h3 style="color: var(--accent);"><i class="fas fa-history"></i> Activity History</h3>
        <span class="badge" style="background: rgba(0, 217, 255, 0.2); color: var(--accent); padding: 0.5rem 1rem; border-radius: 20px;">
            {{ logs|length }} records
        </span>
    </div>
    
    {% if logs %}
    <div style="overflow-x: auto;">
        <table class="data-table">
            <thead>
                <tr>
                    <th style="width: 20%;"><i class="fas fa-tag"></i> Action</th>
                    <th style="width: 35%;"><i class="fas fa-info-circle"></i> Details</th>
                    <th style="width: 20%;"><i class="fas fa-network-wired"></i> IP Address</th>
                    <th style="width: 25%;"><i class="fas fa-clock"></i> Timestamp</th>
                </tr>
            </thead>
            <tbody>
                {% for log in logs %}
                <tr style="transition: var(--transition);">
                    <td>
                        <span class="activity-badge {{ 
                            'badge-success' if 'SUCCESS' in log[0] else 
                            'badge-danger' if 'FAILED' in log[0] else 
                            'badge-warning' if 'TRADE' in log[0] else 
                            'badge-info' }}" 
                              style="display: inline-block; padding: 0.4rem 0.8rem; border-radius: 12px; font-size: 0.85rem; font-weight: 600;">
                            {% if 'LOGIN' in log[0] %}
                                <i class="fas fa-sign-in-alt"></i>
                            {% elif 'LOGOUT' in log[0] %}
                                <i class="fas fa-sign-out-alt"></i>
                            {% elif 'TRADE' in log[0] %}
                                <i class="fas fa-exchange-alt"></i>
                            {% elif 'DASHBOARD' in log[0] %}
                                <i class="fas fa-home"></i>
                            {% elif 'PROFILE' in log[0] %}
                                <i class="fas fa-user-edit"></i>
                            {% elif 'FILE' in log[0] %}
                                <i class="fas fa-upload"></i>
                            {% elif 'SESSION' in log[0] %}
                                <i class="fas fa-clock"></i>
                            {% else %}
                                <i class="fas fa-circle"></i>
                            {% endif %}
                            {{ log[0] }}
                        </span>
                    </td>
                    <td style="color: var(--text);">{{ log[1] }}</td>
                    <td>
                        <code style="background: rgba(110, 86, 207, 0.2); padding: 0.3rem 0.6rem; border-radius: 4px; 
                                     font-family: 'JetBrains Mono', monospace; color: var(--accent); font-size: 0.85rem;">
                            {{ log[2] }}
                        </code>
                    </td>
                    <td style="color: var(--text-muted); font-size: 0.9rem;">
                        <i class="fas fa-calendar-alt" style="margin-right: 0.5rem;"></i>
                        {{ log[3][:19] }}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    
    <!-- Export Options -->
    <div style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border); display: flex; gap: 1rem; justify-content: flex-end;">
        <button class="btn btn-secondary" onclick="exportToCSV()">
            <i class="fas fa-file-csv"></i> Export CSV
        </button>
        <button class="btn btn-secondary" onclick="window.print()">
            <i class="fas fa-print"></i> Print
        </button>
    </div>
    
    {% else %}
    <div style="text-align: center; padding: 3rem;">
        <i class="fas fa-inbox" style="font-size: 4rem; color: var(--text-muted); opacity: 0.5; margin-bottom: 1rem;"></i>
        <h3 style="color: var(--text-secondary); margin-bottom: 0.5rem;">No activities found</h3>
        <p style="color: var(--text-muted);">Start using the platform to see your activity logs here</p>
    </div>
    {% endif %}
</div>

<style>
    .badge-success { background: rgba(0, 255, 136, 0.2); color: var(--success); }
    .badge-danger { background: rgba(255, 77, 109, 0.2); color: var(--danger); }
    .badge-warning { background: rgba(255, 215, 0, 0.2); color: var(--gold); }
    .badge-info { background: rgba(0, 217, 255, 0.2); color: var(--accent); }
    
    @media print {
        .navbar, .sidebar, .btn, .glass-card:has(form) { display: none !important; }
        body { background: white; color: black; }
        .glass-card { border: 1px solid #ccc; background: white; }
    }
</style>

<script>
    function exportToCSV() {
        const table = document.querySelector('.data-table');
        let csv = [];
        const rows = table.querySelectorAll('tr');
        
        for (let i = 0; i < rows.length; i++) {
            const row = [], cols = rows[i].querySelectorAll('td, th');
            for (let j = 0; j < cols.length; j++) {
                let text = cols[j].innerText.replace(/"/g, '""');
                row.push('"' + text + '"');
            }
            csv.push(row.join(','));
        }
        
        const csvFile = new Blob([csv.join('\n')], { type: 'text/csv' });
        const downloadLink = document.createElement('a');
        downloadLink.download = 'activity_logs_' + new Date().toISOString().split('T')[0] + '.csv';
        downloadLink.href = window.URL.createObjectURL(csvFile);
        downloadLink.style.display = 'none';
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
    }
</script>
{% endblock %}''',
    }

    for filename, content in templates.items():
        path = f'templates/{filename}'
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

if __name__ == '__main__':
    init_db()
    create_templates()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    print("CryptoTrader Pro - Modern UI Edition Ready!")
    print("Visit: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)