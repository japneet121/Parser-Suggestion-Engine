#!/usr/bin/python3
import os
from flask import Flask, render_template, request, redirect, url_for
#from flask_mail import Mail, Message

from form_contact import ContactForm, csrf
from suggestions import get_suggestions
from parsers import get_parser_suggestion_html
import json
from flask import request
#mail = Mail()

app = Flask(__name__)

SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
csrf.init_app(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'yourId@gmail.com'
app.config['MAIL_PASSWORD'] = '*****'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

#mail.init_app(app)

@app.route('/')
def index():
    form = ContactForm()
    return render_template('views/contacts/contact.html', form=form)

@app.route('/contact', methods=['POST', 'GET'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():        
        print('-------------------------')
        print(request.form['json'])
        print('-------------------------')
        #send_message(request.form)
        suggestions=get_suggestions(json.loads(request.form['json']))
        field_html=suggestions[0].to_html(classes=['thead-light','table','table-hover','table-striped'],index=False)
        factor_html=suggestions[1].to_html(classes=['thead-light','table-hover','table','table-striped'],index=False)
        parsers=suggestions[2]
        return redirect(url_for(".show_suggestions",fields=field_html,factors=factor_html,parsers=parsers))    

    return render_template('views/contacts/contact.html', form=form)

@app.route('/success')
def success():
    return render_template('views/home/index.html')

@app.route('/show_suggestions')
def show_suggestions():
    fields=request.args.get('fields')
    factors=request.args.get('factors')
    parsers=request.args.get('parsers')
    print('getting suggestion')

    return render_template('views/suggestions/suggestions.html',fields=fields,factors=factors,parsers=parsers)

@app.route('/suggestions',methods=['POST'])
def suggestions():
    suggestions=get_suggestions(json.loads(request.form['json']))
    print(suggestions)
    return(suggestions)

def send_message(message):
    print(message.get('name'))

    msg = Message(message.get('subject'), sender = message.get('email'),
            recipients = ['id1@gmail.com'],
            body= message.get('message')
    )  
    mail.send(msg)

if __name__ == "__main__":
    app.run(debug = True)