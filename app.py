import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd, validate, greeting

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # create table in database to store stocks owned by user if it doesn't exist already
    table_name = "table_" + str(session["user_id"])
    db.execute("CREATE TABLE IF NOT EXISTS ?(Symbol TEXT NOT NULL, Shares INT NOT NULL, Price INT NOT NULL, Transacted TEXT NOT NULL)", table_name)

    # Select stocks that the user owns atleast 1 share in
    tickers = db.execute("SELECT Symbol, SUM(Shares) FROM ? GROUP BY upper(Symbol)", table_name)
    print(tickers)

    filter_tickers = [ticker for ticker in tickers if (ticker["SUM(Shares)"] != 0)]

    # Check how much cash the user has in their account
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])

    sum = 0
    # Determine the total value of all stocks owned
    for ticker in filter_tickers:
        sum += ticker["SUM(Shares)"]*lookup(ticker["Symbol"])["price"]

    # Generate welcome message at main menu
    Msg = greeting() + session["username"] + ""

    return render_template("home.html", tickers=filter_tickers, search=lookup, cash=cash[0]['cash'], sum=sum, Msg=Msg)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    '''Allow users to enter in personal information and change password'''
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        new_password_confirm = request.form.get("new_password_confirm")

        # Retrieve current hash of user's password stored in database
        current_pass_hash = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])

        # Check to see if all input fields were completed
        if not old_password or not new_password or not new_password_confirm:
            return apology("Password field is missing")

        # Check to see if user has confirmed their new password successfully, then check to see if user has entered in their correct current password
        if new_password == new_password_confirm:
            if check_password_hash(current_pass_hash[0]["hash"], old_password):
                db.execute("Update users SET hash = ? WHERE id = ?", generate_password_hash(new_password), session["user_id"])
            else:
                return apology("Current password entered is not correct")
        else:
            return apology("Please confirm new password")

        flash("Password has been successfully changed")
        return redirect("/account")

    else:
        return render_template("account.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # create table in database to store stocks owned by user
        table_name = "table_" + str(session["user_id"])
        db.execute("CREATE TABLE IF NOT EXISTS ?(Symbol TEXT NOT NULL, Shares INT NOT NULL, Price INT NOT NULL, Transacted TEXT NOT NULL)", table_name)

        symbol = request.form.get("symbol").lower()
        share_count = request.form.get("shares")

        # check if info was entered
        if not symbol or not share_count:
            return apology("Ticker or number of share input is blank")

        # check if ticker exists
        if lookup(symbol) == None:
            return apology("Valid API key is missing or ticker does not exist")

        # Handle fractional, negative and non-numeric input
        try:
            share_count = int(share_count)
        except ValueError:
            return apology("Number of shares must be an integer")

        if((share_count) <= 0):
            return apology("Number of shares must be positive")

        # check to see if user has enough money to purchase X number of shares at Y per share
        stock_info = lookup(symbol)
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])
        cost = stock_info["price"] * share_count
        check = float(balance[0]["cash"])
        if cost < check:

            # if user has enough, execute trade and update user's cash balance and stocks owned
            remaining = round((balance[0]["cash"] - cost), 2)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", remaining, session['user_id'])
            db.execute("INSERT INTO ?(Symbol, Shares, Price, Transacted) VALUES (?,?,?, CURRENT_TIMESTAMP)",
                       table_name, symbol.upper(), share_count, stock_info["price"])

            flash("Purchase " + str(share_count) + " of " +
                  symbol.upper() + " for amount " + str(stock_info["price"]) + " passed successfully.")
            return redirect("/")
        else:
            return apology("Not enough funds to execute transation")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # retrieve data of all stock purchased and display on page
    table_name = "table_" + str(session["user_id"])
    tickers = db.execute("SELECT Symbol, Shares, Price, Transacted FROM ?", table_name)

    return render_template("history.html", tickers=tickers)


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
        session["username"] = rows[0]["username"]
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

        symbol = request.form.get("symbol")

        # validate user input then check price of stock
        if not symbol:
            return apology("Ticker input is blank")
        if lookup(symbol) == None:
            return apology("Valid API key is missing or ticker does not exist")
        else:
            stock_info = lookup(symbol)
            return render_template("quoted.html", stock_info=stock_info)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':

        name = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # check to see if username already exists and if user entered in password details correctly
        current_user = db.execute("SELECT * FROM users WHERE username = ?", name)
        if not name or len(current_user) == 1:
            return apology("User’s input is blank or the username already exists")
        elif not password or password != confirmation:
            return apology("Either password input is blank or the passwords do not match")

        # check to see if password meets character requirements
        elif validate(password) != True:
            return validate(password)

        else:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", name, generate_password_hash(password))
            flash("Registered!")
            return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    table_name = "table_" + str(session["user_id"])
    tickers = db.execute("SELECT Symbol, SUM(Shares) FROM ? GROUP BY upper(Symbol)", table_name)

    # determine stocks that are currently owned by the user
    tickers_bought = [ticker for ticker in tickers if (ticker["SUM(Shares)"] != 0)]

    if request.method == "POST":

        '''store stock and # of shares to be sold'''
        stock = request.form.get("symbol")
        share_count = (request.form.get("shares"))

        # validate user input
        if not stock or not share_count:
            return apology("Ticker and/or number of shares to be sold is missing")
        elif(int(share_count) <= 0):
            return apology("Number of shares must be positive")
        else:
            share_count = int(share_count)

        # check to see if the user owns the stock they wish to sell
        found = 0
        for i in tickers_bought:
            if i["Symbol"] == stock:
                found = 1
                break

        if found == 1:
            # Check if user has enough shares to sell
            share_check = db.execute("SELECT SUM(Shares) FROM ? WHERE Symbol = ? GROUP BY Symbol", table_name, stock)
            stock_data = lookup(stock)

            balance = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])
            payment = stock_data["price"] * share_count

            if((share_check[0]["SUM(Shares)"]) >= share_count):
                db.execute("UPDATE users SET cash = ? WHERE id = ?", balance[0]["cash"] + payment, session['user_id'])
                db.execute("INSERT INTO ?(Symbol, Shares, Price, Transacted) VALUES (?,?,?, CURRENT_TIMESTAMP)",
                           table_name, stock_data["symbol"], -1 * share_count, stock_data["price"])

            else:
                return apology("Not enough shares owned")

            flash("Selling " + str(share_count)  +
                  stock_data["symbol"].upper() + " for amount " + str(stock_data["price"]) + " passed successfully.")
            return redirect('/')
        else:
            return apology("Stock not owned")
    else:
        return render_template("sell.html", tickers_bought=tickers_bought)