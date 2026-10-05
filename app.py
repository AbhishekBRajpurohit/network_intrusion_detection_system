"""Unprivileged, local Flask dashboard. Capture runs separately in sniffer.py."""
import csv
import io
import json
import os
import secrets
from datetime import timedelta, datetime, timezone
from functools import wraps
from pathlib import Path
import click
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from utils import logger as db


def create_app(test_config=None):
    app=Flask(__name__)
    app.config.update(SECRET_KEY=os.getenv('NIDS_SECRET_KEY') or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_SECURE=os.getenv('NIDS_HTTPS')=='1',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),MAX_CONTENT_LENGTH=1024*1024)
    if test_config: app.config.update(test_config)
    db.init_db()

    @app.before_request
    def protect():
        if request.method=='POST':
            token=request.form.get('csrf') or request.headers.get('X-CSRF-Token','')
            if not token or not secrets.compare_digest(token,session.get('csrf','')): abort(400,'Invalid CSRF token')
        if request.endpoint not in ('login','static') and not session.get('username'):
            if request.path.startswith('/api/') or request.path.startswith('/export/'):
                return jsonify(error='Login required'),401
            return redirect(url_for('login'))

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Cache-Control']='no-store'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'"
        return response

    @app.errorhandler(ValueError)
    def invalid(exc): return jsonify(error=str(exc)),400

    @app.route('/login',methods=['GET','POST'])
    def login():
        session.setdefault('csrf',secrets.token_hex(32))
        error=None
        if request.method=='POST':
            with db.connect() as c:
                user=c.execute('SELECT * FROM users WHERE username=?',(request.form.get('username',''),)).fetchone()
            if user and check_password_hash(user['password_hash'],request.form.get('password','')):
                session.clear();session.update(username=user['username'],csrf=secrets.token_hex(32))
                session.permanent=True
                return redirect(url_for('index'))
            error='Incorrect username or password.'
        return render_template('login.html',error=error)

    @app.post('/logout')
    def logout(): session.clear();return redirect(url_for('login'))

    @app.get('/')
    def index():return render_template('index.html')

    @app.get('/api/<table>')
    def rows(table):
        if table not in ('traffic','alerts'):abort(404)
        page=max(1,int(request.args.get('page',1)))
        limit=min(100,max(1,int(request.args.get('limit',25))))
        return jsonify(**db.query(table,request.args,limit,(page-1)*limit),page=page,limit=limit)

    @app.get('/api/stats')
    def stats(): return jsonify(db.stats(request.args))

    @app.get('/api/status')
    def status(): return jsonify(db.get_status())

    @app.get('/api/audit')
    def audit():
        with db.connect() as c:
            return jsonify([dict(r) for r in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100')])

    @app.get('/export/<table>.csv')
    def export_csv(table):
        if table not in ('traffic','alerts'):abort(404)
        result=db.query(table,request.args,100001)
        if result['total']>100000:abort(400,'Narrow filters to at most 100,000 records')
        out=io.StringIO();writer=csv.writer(out)
        fields=['timestamp','src_ip','dst_ip','protocol', 'label' if table=='traffic' else 'attack_type',
                'source','severity','confidence','reason','features']
        writer.writerow(fields)
        for row in result['rows']:
            values=[]
            for field in fields:
                value=row.get(field)
                if isinstance(value,dict):value=json.dumps(value)
                if isinstance(value,str) and value.lstrip().startswith(('=','+','-','@','\t','\r')):value="'"+value
                values.append(value)
            writer.writerow(values)
        return send_file(io.BytesIO(out.getvalue().encode('utf-8-sig')),mimetype='text/csv',as_attachment=True,download_name=table+'.csv')

    @app.get('/export/report.pdf')
    def pdf():
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from xml.sax.saxutils import escape
        result=db.stats(request.args);out=io.BytesIO();styles=getSampleStyleSheet()
        elements=[]
        def para(value,style='BodyText'):
            elements.append(Paragraph(escape(str(value)),styles[style]));elements.append(Spacer(1,8))
        para('NIDS Incident Summary','Title')
        para('Generated '+datetime.now(timezone.utc).isoformat())
        para('Filters: '+json.dumps(dict(request.args)))
        para(f"Retained traffic records: {result['traffic']} | Alerts: {result['alerts']}")
        para('Detection status: '+json.dumps(db.get_status()))
        para('Attack breakdown','Heading2')
        for item in result['attacks']:para(f"{item['attack_type']}: {item['count']}")
        para('Latest 50 matching incidents','Heading2')
        for row in db.query('alerts',request.args,50)['rows']:
            para(f"{datetime.fromtimestamp(row['timestamp'],timezone.utc).isoformat()} | {row['src_ip']} | {row['attack_type']} | {row['source']} | {row['severity']}")
            para(row['reason'])
        para('Blocking outcomes','Heading2')
        para('Historical blocked flags are not proof of a current firewall rule. Live capture is alert-only.')
        with db.connect() as c:
            for row in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 20'):
                para(f"Audit (latest 20, all times): {row['action']} {row['ip']} success={bool(row['success'])}: {row['detail']}")
        SimpleDocTemplate(out,pagesize=A4).build(elements);out.seek(0)
        return send_file(out,mimetype='application/pdf',as_attachment=True,download_name='nids-report.pdf')

    @app.cli.command('create-admin')
    @click.option('--username',prompt=True)
    @click.password_option()
    def admin(username,password):
        if not username.strip():raise click.ClickException('Username cannot be empty')
        if len(password)<12:raise click.ClickException('Use at least 12 characters')
        with db.connect() as c:
            if c.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone():
                raise click.ClickException('User already exists')
            c.execute('INSERT INTO users VALUES(?,?)',(username,generate_password_hash(password)))
        click.echo('Admin created. Start python app.py, then sign in.')
    return app

app=create_app()
if __name__=='__main__':app.run(host='127.0.0.1',port=5000,debug=False)