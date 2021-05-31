import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from math import floor
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get number of rows from table
    rows = db.execute("SELECT symbol FROM stocks")

    # Update all of the stock prices
    for i in range(0, len(rows)):
        stock_info = lookup(rows[i]["symbol"])
        db.execute("UPDATE stocks SET price = ? WHERE symbol = ?", usd(stock_info["price"]), rows[i]["symbol"])

    # Removes stocks that have been totally sold
    db.execute("DELETE FROM stocks WHERE shares = 0")

    # Return webpage with relevant info
    stocks = db.execute("SELECT * FROM stocks WHERE person_id = ?", session["user_id"])
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    return render_template("index.html", stocks=stocks, cash=usd(user_cash[0]["cash"]))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Get form info
        symbol_name = request.form.get("symbol")
        share_num = request.form.get("shares")
        symbol_name = symbol_name.upper()
        # Get user cash amount
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

        # Get stock info and check if stock symbol exists
        stock_info = lookup(symbol_name)
        if stock_info == None:
            return apology("invalid symbol")

        # Checks if there is sufficient cash in account
        if stock_info["price"] * float(share_num) > cash[0]["cash"]:
            return apology("not enough money")

        # Updates user cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash[0]["cash"] -
                   stock_info["price"] * float(share_num), session["user_id"])

        # Check if stock has been previously purchased
        previous_stocks = db.execute("SELECT symbol FROM stocks WHERE symbol = ?", symbol_name)
        if len(previous_stocks) > 0:

            # Instead of creating a new row, we add the total and the share number purchased
            previous_share_num = db.execute("SELECT shares FROM stocks WHERE symbol = ?", symbol_name)
            new_share_num = share_num + previous_share_num[0]["shares"]
            db.execute("UPDATE stocks SET shares = ? WHERE symbol = ? AND person_id = ?",
                       new_share_num, symbol_name, session["user_id"])
            db.execute("UPDATE stocks SET total = ? WHERE symbol = ? AND person_id = ?", usd(
                stock_info["price"] * float(new_share_num)), symbol_name, session["user_id"])

        else:

            # Record new transaction
            db.execute("INSERT INTO stocks (person_id, symbol, shares, price, total) VALUES (?, ?, ?, ?, ?)",
                       session["user_id"], symbol_name, share_num, usd(stock_info["price"]), usd(stock_info["price"] * float(share_num)))

        # Record new transaction
        db.execute("INSERT INTO transactions (person_id, symbol, shares, total, time) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol_name, share_num, "-" + usd(stock_info["price"] * float(share_num)), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute("SELECT * FROM transactions WHERE person_id = ?", session["user_id"])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":

        # Get form info
        symbol_name = request.form.get("symbol")
        stock_info = lookup(symbol_name)

        # Check if symbol exists
        if stock_info == None:
            return apology("invalid symbol")

        # Return result page
        return render_template("quote_result.html", name=stock_info["name"], price=usd(stock_info["price"]), symbol=stock_info["symbol"])

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")
        
        # Check confirmation
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("must confirm password")
        
        # Query database for possible username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username does not exist
        if len(rows) != 0:
            return apology("username unavailable")

        # Hashes password and inserts username and hash into database
        hashed_password = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), hashed_password)

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        # Get all relevant info
        rows = db.execute("SELECT symbol FROM stocks")
        symbol = request.form.get("symbol")
        share_num = request.form.get("shares")

        # Update all of the stock prices
        for i in range(0, len(rows)):
            stock_info = lookup(rows[i]["symbol"])
            db.execute("UPDATE stocks SET price = ? WHERE symbol = ?", usd(stock_info["price"]), rows[i]["symbol"])

        # Checks if symbol is inputted
        if not symbol:
            return apology("please input symbol")

        # Gets number of stock shares
        stock_shares = db.execute("SELECT shares from stocks where symbol = ?", symbol)

        # Checks whether the number is valid
        if int(share_num) > stock_shares[0]["shares"] or not share_num:
            return apology("please input valid integer")

        # Gets relevant info
        stock_info = lookup(symbol)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        shares = db.execute("SELECT shares FROM stocks WHERE symbol = ? AND person_id = ?", symbol, session["user_id"])

        # Reformats the total number from string to float
        total = db.execute("SELECT total FROM stocks WHERE symbol = ? AND person_id = ?", symbol, session["user_id"])
        total_num = total[0]["total"][1:]
        total_num = total_num.replace(",", "")

        # Updates user cash and share numbers
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash[0]["cash"] +
                   stock_info["price"] * float(share_num), session["user_id"])
        db.execute("UPDATE stocks SET shares = ? WHERE person_id = ? AND symbol = ?",
                   shares[0]["shares"] - int(share_num), session["user_id"], symbol)
        db.execute("UPDATE stocks SET total = ? WHERE person_id = ? AND symbol = ?", usd(
            float(total_num) - stock_info["price"] * float(share_num)), session["user_id"], symbol)

        # Records the transaction
        db.execute("INSERT INTO transactions (person_id, symbol, shares, total, time) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol, 0 - int(share_num), usd(stock_info["price"] * float(share_num)), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        return redirect("/")

    stocks = db.execute("SELECT * FROM stocks WHERE person_id = ?", session["user_id"])
    return render_template("sell.html", stocks=stocks)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow user to change password"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("old_password"):
            return apology("must provide old password", 403)

        # Ensure password was submitted
        elif not request.form.get("new_password"):
            return apology("must provide new_password", 403)

        # Check if passwords are the same
        if request.form.get("old_password") == request.form.get("new_password"):
            return apology("password may not be the same")

        # Get hashed password for current user
        rows = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])

        # Checks if old password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
            return apology("invalid old password", 403)

        # Generates the new hash and updates user table
        hashed_password = generate_password_hash(request.form.get("new_password"))
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashed_password, session["user_id"])

        return redirect("/")

    else:
        return render_template("change_password.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
