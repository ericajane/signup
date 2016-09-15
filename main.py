#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re

#name, password, verify password, email
form="""
<!DOCTYPE html>
<html>
    <head>
        <style>
            .error {
                color: red;
            }
        </style>

    </head>
    <body>
        <h1>Sign up here for my awesome members-only site, yo!</h1>
            <form method="post">
            <div>
                <label for="username">Enter your username:</label>
                <input name="username" type="text" value="%(username)s">
                <p class="error">%(error_username)s</p>
            </div>
            <div>
                <label for="password">Enter your password:</label>
                <input name="password" type="password" value="%(password)s">
                <p class="error">%(error_password)s</p>
            </div>
            <div>
                <label for="verify">Enter your password again:</label>
                <input name="verify" type="password" value="%(verify)s">
                <p class="error">%(error_verify)s</p>
            </div>
            <div>
                <label for="email">Enter your email:</label>
                <input name="email" type="email" value="%(email)s">
                <p class="error">%(error_email)s</p>
            </div>
            <br>
            <input type="submit">
            </form>
        </body>
    </html>
"""
#defines what is and is not valid

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class MainHandler(webapp2.RequestHandler):

#defines write_form so it can be called
    def write_form(self, username="", error_username="", password="", error_password="", verify="", error_verify="", email="", error_email=""):
        self.response.out.write(form % {"username": username,
                                        "password": password,
                                        "verify": verify,
                                        "email": email,
                                        "error_username": error_username,
                                        "error_password": error_password,
                                        "error_verify": error_verify,
                                        "error_email": error_email})
    def get(self):
        self.write_form()

    def post(self):
        have_error = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = dict(username = username, email = email)

        if not valid_username(username):
            params['error_username'] = "Not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "Not a valid password."
            have_error = True

        elif password != verify:
            params['error_verify'] = "Passwords don't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "Not a valid email."
            have_error = True
        #regenerates form so user can correct errors
        if have_error:
            self.write_form(**params)
        #redirects user to welcome page if signup is successful (no errors)
        else:
            self.redirect('/welcome?username=' + username)

class Welcome(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.response.out.write("Welcome, {0}" .format(username))
        else:
            self.redirect('/')





app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', Welcome)
    ], debug=True)
