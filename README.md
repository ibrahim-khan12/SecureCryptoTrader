# 🚀 CryptoTrader Pro

CryptoTrader Pro is a modern, secure, and feature-rich cryptocurrency trading simulation platform built with Flask and SQLite. It provides a realistic trading experience, robust security, and a visually appealing cyber-inspired UI. This project is ideal for learning, demos, and as a foundation for real-world crypto trading applications.

---

## 🛡️ Features

### User Management
- **Registration & Login:** Secure authentication with strong password validation (min 8 chars, upper/lower/digit/special).
- **Account Lockout:** Automatic lock after 5 failed login attempts (15 min lock).
- **Session Timeout:** Auto-logout after 5 minutes of inactivity.
- **Profile Management:** Update personal info, encrypted government ID storage, and bio.

### Trading & Portfolio
- **Dashboard:** Real-time overview of portfolio value, USD balance, assets held, recent transactions, and watchlist.
- **Trading:** Buy/sell supported cryptocurrencies (BTC, ETH, BNB, SOL, ADA, DOT, MATIC, LINK) with demo balance.
- **Holdings:** Track all crypto assets, purchase prices, and profit/loss.
- **Markets:** View live prices and market trends for supported coins.
- **Portfolio:** Detailed view of holdings, transaction history, and performance.

### Security
- **Input Sanitization:** Prevents SQL injection and XSS attacks.
- **Password Hashing:** Secure password storage using Scrypt.
- **Data Encryption:** Sensitive data (notes, government ID) encrypted with Fernet (AES).
- **Audit Logging:** All user actions tracked for security and compliance.

### File Uploads
- **Secure Uploads:** Upload documents (PDF, JPG, JPEG, PNG) with type and size validation (max 5MB).
- **Audit Trail:** All uploads logged for review.

### Activity Logs & Analytics
- **Comprehensive Logs:** View all user activities (login, trades, profile updates, uploads, dashboard views).
- **Statistics:** See total activities, active days, logins, trades, profile updates.
- **Visual Analytics:** Interactive charts for last 7 days activity, top actions, and trends.
- **Advanced Filtering:** Filter logs by action type and date range.
- **Export & Print:** Download logs as CSV or print directly.

### Modern UI
- **Responsive Design:** Works on desktop and mobile.
- **Dark Theme:** Cyberpunk-inspired, visually appealing interface.
- **Password Visibility Toggle:** Easily show/hide passwords in forms.
- **Interactive Components:** Animated charts, badges, and transitions.

## 🖥️ Technologies Used

- **Python 3.8+** — Main programming language
- **Flask** — Web framework for backend and routing
- **SQLite** — Lightweight relational database
- **Werkzeug** — Secure password hashing and utilities
- **Cryptography (Fernet)** — Data encryption for sensitive fields
- **Jinja2** — Templating engine for HTML pages
- **HTML5 & CSS3** — Responsive, modern UI
- **JavaScript** — UI interactivity (password toggle, charts, export)
- **Font Awesome** — Icon library for UI elements

---

## 🏁 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/ibrahim-khan12/CryptoTraderPro.git
cd CryptoTraderPro
```

### 2. Install Dependencies
```bash
pip install flask werkzeug cryptography
```

### 3. Run the Application
```bash
python CryptoTradingPlatform.py
```

### 4. Access the App
- Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## 📁 Folder Structure

```
CryptoTradingPlatform.py      # Main Flask application
crypto_platform.db            # SQLite database (auto-created)
templates/                    # HTML templates (modern UI)
crypto_uploads/               # Uploaded files (auto-created)
crypto_key.key                # Encryption key (auto-generated)
crypto_trading.log            # Audit log file
```

---

## 🔒 Security Highlights

- Passwords never stored in plain text.
- Sensitive data encrypted with Fernet/AES.
- All user actions logged for auditing.
- Input/output sanitized to prevent attacks.
- Account lockout and session timeout for protection.

---

## 📊 Demo Data & Supported Coins

- **Demo Balance:** New users start with $10,000 USD.
- **Supported Coins:** BTC, ETH, BNB, SOL, ADA, DOT, MATIC, LINK.
- **Sample Users:** Register via the app; no default admin account.

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).



---

## 💡 Contributing

Pull requests, issues, and suggestions are welcome!  
Feel free to fork, modify, and extend for your own use.

---

> **Made with ❤️ for crypto trading demos.**

