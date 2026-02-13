@app.route("/user", methods=["GET"])
def viewUser():
    userID = request.cookies.get("userID")
    if not is_logged_in(request) or not userID: 
        return make_response(redirect("/login"))
    try:
        userID = int(userID)
        with open("users/" + str(userID)) as f:
            return render_template("user.html", text=f.read().splitlines(), logged_in=True)
    except: 
        return render_template("user.html", text=[f"Error: {str(userID)} is not a valid user ID"], logged_in=True)