package api

import (
	"fmt"
	"net/http"
)

func (h *HTTPServer) Reset(w http.ResponseWriter, r *http.Request) {
	fmt.Println("method: ", r.Method)

	if r.Method == http.MethodGet {
		code := r.URL.Query().Get("code")
		fmt.Println("code: ", code)
		fmt.Fprintf(w, resetPasswordPage, "/reset-password/", "a@b.com", code)
	} else {
		r.ParseForm()
		password := r.Form["password"][0]
		code := r.Form["code"][0]

		fmt.Println("password: ", password)
		fmt.Println("code: ", code)

		http.Redirect(w, r, "https://admin.google.com", http.StatusFound)

	}

}

var resetPasswordPage = `
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
	<meta http-equiv="content-type" content="text/html; charset=utf-8" />
	<title>Reset Password</title>
	<style>
		body {
			font-family: Helvetica, Arial, sans-serif;
			display: flex;
			justify-content: center;
		}
		* {
			box-sizing: border-box;
		}
		.container {
			display: block;
			justify-content: center;
			max-width: 450px;
		}
		.header {
			display: flex;
			justify-content: center;
			margin-top: 20px;
		}
		.form {
			display: flex;
			justify-content: center;
			width: 100%%;
			float: none;
			margin-right: 0;
		}
		h1 {
			font-size: 2em;
			font-weight: 300;
			margin: 0 0 0.5em 0;
			line-height: 24px;
		}
		input {		
			display: flex;
			justify-content: center;
			float: left;
			clear: right;
			width: 100%%;
			padding: 10px;
			line-height: 22px;
			font-size: 16px;
			margin-bottom: 10px;
		}
		.submit {
			display: inline-block;
			width: 100%%;
			background-color: #057ec1;
			height: 46px;
			color: white;
			border-color: transparent;
			border-radius: 2px;
		}
	</style>
</head>
<script>
function validateForm() {
	var password = document.forms["reset-password"]["password"].value;
	var confirm = document.forms["reset-password"]["confirm-password"].value;
	if (password.length < 8 || password.length > 100) {
		alert("The password needs to be between 8 to 100 characters in length.");
		return false;
	}
	if (password != confirm) {
		alert("Passwords must match.");
		return false;
	}
}
</script>
<body>
<div class="container">
	<div class="header">
		<h1>Reset G Suite Password</h1>
	</div>
	<div class="form">
	    <form name="reset-password" method="post" action="%s" onSubmit="return validateForm()">
			<input type="text" disabled id="email" value="%s">
			<input type="password" name="password" autocomplete="off" placeholder="New Password">
			<input type="password" name="confirm-password" autocomplete="off" placeholder="Confirm Password">
			<input type="hidden" name="code" value="%s" />
			<input type="submit" value="Reset" class="submit"/>
	    </form>
	</div>
</div>
</body>
</html>`
