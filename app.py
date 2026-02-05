from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'ustm_prom_night_secret'

# 1. SETUP DATABASE & UPLOADS
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prom_lite.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# 2. DATABASE MODELS
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50)) 
    
    # NEW FIELDS
    dept = db.Column(db.String(50))
    semester = db.Column(db.String(20))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    
    # PROFILE FIELDS
    hobbies = db.Column(db.String(200), default="")
    interests = db.Column(db.String(200), default="")
    bio = db.Column(db.String(300), default="")
    
    id_card_img = db.Column(db.String(100))
    profile_img = db.Column(db.String(100))
    
    # Flags
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.Integer)
    receiver = db.Column(db.Integer)
    status = db.Column(db.String(20))

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer)
    reported_id = db.Column(db.Integer)
    reason = db.Column(db.String(200))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer)
    receiver_id = db.Column(db.Integer)
    content = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.now)

# --- GOLDEN TICKET MODEL ---
class GoldenTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer)
    receiver_id = db.Column(db.Integer)
    status = db.Column(db.String(20), default='pending') # pending, accepted, rejected
    timestamp = db.Column(db.DateTime, default=datetime.now)

# 3. ROUTES AND ERROR HANDLERS

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/')
def home():
    if 'user_id' not in session: 
        return render_template('landing.html')

    me = User.query.get(session['user_id'])
    
    if not me: 
        session.pop('user_id', None)
        return redirect('/')

    if me.is_banned: 
        flash('Your account has been BANNED.', 'error')
        return render_template('login.html')
        
    if me.is_admin: return redirect('/admin')
    
    if not me.is_verified:
        return "<h1>⏳ Account Pending Verification by Admin.</h1><a href='/logout'>Logout</a>"

    # --- GOLDEN TICKET CHECK ---
    received_ticket = GoldenTicket.query.filter_by(receiver_id=me.id, status='pending').first()
    ticket_sender = None
    if received_ticket:
        ticket_sender = User.query.get(received_ticket.sender_id)

    my_date_ticket = GoldenTicket.query.filter(
        ((GoldenTicket.receiver_id == me.id) | (GoldenTicket.sender_id == me.id)) & 
        (GoldenTicket.status == 'accepted')
    ).first()
    
    my_date = None
    if my_date_ticket:
        partner_id = my_date_ticket.sender_id if my_date_ticket.receiver_id == me.id else my_date_ticket.receiver_id
        my_date = User.query.get(partner_id)

    # Standard Match Logic
    interacted_ids = [m.receiver for m in Match.query.filter_by(sender=me.id).all()]
    reported_ids = [r.reported_id for r in Report.query.filter_by(reporter_id=me.id).all()]
    excluded_ids = interacted_ids + reported_ids + [me.id]
    
    target_gender = 'Female' if me.gender == 'Male' else 'Male'

    person = User.query.filter(
        User.is_verified == True, 
        User.is_banned == False,
        User.gender == target_gender,
        ~User.id.in_(excluded_ids)
    ).first()
    
    return render_template('home.html', me=me, person=person, 
                         ticket_sender=ticket_sender,
                         my_date=my_date)

# --- GOLDEN TICKET ROUTES ---

@app.route('/golden_ticket/send/<int:target_id>')
def send_golden_ticket(target_id):
    me_id = session['user_id']
    existing = GoldenTicket.query.filter(
        (GoldenTicket.sender_id == me_id) & 
        (GoldenTicket.status != 'rejected')
    ).first()
    
    if existing:
        flash("You have already used your Golden Ticket! If it was rejected, you can try again.", "error")
        return redirect('/matches')

    new_ticket = GoldenTicket(sender_id=me_id, receiver_id=target_id)
    db.session.add(new_ticket)
    db.session.commit()
    
    flash("Golden Ticket Sent! Fingers crossed! 🤞", "success")
    return redirect('/matches')

@app.route('/golden_ticket/respond/<string:action>/<int:sender_id>')
def respond_golden_ticket(action, sender_id):
    me_id = session['user_id']
    ticket = GoldenTicket.query.filter_by(sender_id=sender_id, receiver_id=me_id, status='pending').first()
    
    if ticket:
        if action == 'accept':
            ticket.status = 'accepted'
            flash("Congratulations! You have a Prom Date! 💖", "success")
        elif action == 'reject':
            ticket.status = 'rejected'
            flash("Ticket returned. You are still available.", "info")
        db.session.commit()
        
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form['password'] != request.form['confirm_password']:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')

        existing_user = User.query.filter_by(email=request.form['email']).first()
        if existing_user:
            flash('Email already registered! Try logging in.', 'error')
            return render_template('register.html')

        final_dept = request.form['dept']
        if final_dept == 'Other':
            final_dept = request.form['custom_dept']

        id_img = request.files['id_card']
        prof_img = request.files['profile_pic']
        id_filename = secure_filename(id_img.filename)
        prof_filename = secure_filename(prof_img.filename)
        id_img.save(os.path.join(app.config['UPLOAD_FOLDER'], id_filename))
        prof_img.save(os.path.join(app.config['UPLOAD_FOLDER'], prof_filename))

        new_user = User(
            name=request.form['name'],
            email=request.form['email'],
            password=request.form['password'],
            dept=final_dept,
            semester=request.form['semester'],
            age=request.form['age'],
            gender=request.form['gender'],
            id_card_img=id_filename,
            profile_img=prof_filename
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect('/login')
    return render_template('register.html')

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session: return redirect('/login')
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        user.name = request.form['name']
        user.bio = request.form['bio']
        user.hobbies = request.form['hobbies']
        user.interests = request.form['interests']
        
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.profile_img = filename
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect('/')
        
    return render_template('edit_profile.html', user=user)

@app.route('/action/<int:target_id>/<action>')
def action(target_id, action):
    me_id = session['user_id']
    if action == 'like':
        check = Match.query.filter_by(sender=target_id, receiver=me_id).first()
        if check:
            check.status = 'matched'
            new_match = Match(sender=me_id, receiver=target_id, status='matched')
            flash("It's a Match! Go say hi!", 'success')
        else:
            new_match = Match(sender=me_id, receiver=target_id, status='pending')
        db.session.add(new_match)
        db.session.commit()
    elif action == 'pass':
        db.session.add(Match(sender=me_id, receiver=target_id, status='passed'))
        db.session.commit()
    return redirect('/')

@app.route('/report/<int:target_id>', methods=['GET', 'POST'])
def report_user(target_id):
    if 'user_id' not in session: return redirect('/login')
    me_id = session['user_id']
    reason_text = "Inappropriate Behavior"
    if request.method == 'POST':
        reason_text = request.form.get('reason', 'Inappropriate Behavior')
    new_report = Report(reporter_id=me_id, reported_id=target_id, reason=reason_text)
    db.session.add(new_report)
    db.session.commit()
    flash('User reported. We will investigate.', 'error')
    return redirect('/')

@app.route('/matches')
def matches():
    me_id = session['user_id']
    
    # 1. Get Regular Matches
    my_matches = Match.query.filter_by(sender=me_id, status='matched').all()
    matched_users = []
    
    # 2. Check Golden Ticket
    my_sent_ticket = GoldenTicket.query.filter(
        (GoldenTicket.sender_id == me_id) & (GoldenTicket.status != 'rejected')
    ).first()
    sent_to_id = my_sent_ticket.receiver_id if my_sent_ticket else None

    # Populate regular matches
    for m in my_matches:
        user = User.query.get(m.receiver)
        if user and not user.is_banned:
            matched_users.append(user)
    
    # 3. UPDATE: Add Admins who have messaged me to the list
    # This allows students to reply to admins
    admin_msgs = Message.query.filter_by(receiver_id=me_id).all()
    for msg in admin_msgs:
        sender = User.query.get(msg.sender_id)
        if sender and sender.is_admin and sender not in matched_users:
            matched_users.insert(0, sender) # Show admins at top

    return render_template('matches.html', users=matched_users, sent_to_id=sent_to_id)

@app.route('/admin')
def admin():
    if 'user_id' not in session: return redirect('/login')
    me = User.query.get(session['user_id'])
    if not me.is_admin: return "Access Denied"
    
    stats = {
        'total_users': User.query.count(),
        'verified': User.query.filter_by(is_verified=True).count(),
        'matches': Match.query.filter_by(status='matched').count() // 2,
        'golden_tickets': GoldenTicket.query.filter_by(status='accepted').count(),
        'boys': User.query.filter_by(gender='Male').count(),
        'girls': User.query.filter_by(gender='Female').count()
    }
    
    all_matches = Match.query.filter_by(status='matched').all()
    matched_couples = []
    seen_pairs = set()

    for m in all_matches:
        pair = tuple(sorted((m.sender, m.receiver)))
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            u1 = User.query.get(pair[0])
            u2 = User.query.get(pair[1])
            if u1 and u2: 
                matched_couples.append({'u1': u1, 'u2': u2})

    accepted_tickets = GoldenTicket.query.filter_by(status='accepted').all()
    golden_couples = []
    for t in accepted_tickets:
        sender = User.query.get(t.sender_id)
        receiver = User.query.get(t.receiver_id)
        if sender and receiver:
            golden_couples.append({'sender': sender, 'receiver': receiver})

    pending = User.query.filter_by(is_verified=False, is_banned=False).all()
    reports_raw = Report.query.all()
    report_list = []
    for r in reports_raw:
        u = User.query.get(r.reported_id)
        if u and not u.is_banned:
            report_list.append({'user': u, 'reason': r.reason})
    active = User.query.filter_by(is_verified=True, is_banned=False, is_admin=False).all()
    
    return render_template('admin.html', 
                         stats=stats, 
                         pending=pending, 
                         reports=report_list, 
                         active=active,
                         matches_list=matched_couples,
                         golden_couples=golden_couples)

@app.route('/approve/<int:user_id>')
def approve(user_id):
    User.query.get(user_id).is_verified = True
    db.session.commit()
    flash('User verified successfully.', 'success')
    return redirect('/admin')

@app.route('/ban/<int:user_id>')
def ban_user(user_id):
    user = User.query.get(user_id)
    user.is_banned = True
    user.is_verified = False
    db.session.commit()
    flash(f'{user.name} has been banned.', 'error')
    return redirect('/admin')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and user.password == request.form['password']:
            if user.is_banned: 
                flash('Access Denied: Your account has been banned.', 'error')
                return render_template('login.html')
            if user.is_admin: 
                flash('Admins must use the Admin Portal.', 'error')
                return render_template('login.html')
            
            session['user_id'] = user.id
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect('/')
        else:
            flash('Invalid email or password.', 'error')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            reset_req = Report(reporter_id=user.id, reported_id=user.id, reason="PASSWORD RESET REQUEST")
            db.session.add(reset_req)
            db.session.commit()
            flash('Reset request sent to Admin! Meet them to get your new password.', 'success')
            return render_template('forgot_password.html', success=True)
        else:
            flash('Email not found.', 'error')
            return render_template('forgot_password.html')
    return render_template('forgot_password.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and user.password == request.form['password'] and user.is_admin:
            session['user_id'] = user.id
            return redirect('/admin')
        flash('Invalid Admin Credentials', 'error')
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect('/') 

# --- UPDATED CHAT UI ---
@app.route('/chat/<int:partner_id>')
def chat_ui(partner_id):
    if 'user_id' not in session: return redirect('/login')
    me_id = session['user_id']
    me = User.query.get(me_id) # Need 'me' object for admin check
    partner = User.query.get(partner_id)
    
    # Bypass Match Logic if Admin is involved
    if me.is_admin or partner.is_admin:
        return render_template('chat.html', partner=partner, me_id=me_id)

    m1 = Match.query.filter_by(sender=me_id, receiver=partner_id, status='matched').first()
    m2 = Match.query.filter_by(sender=partner_id, receiver=me_id, status='matched').first()
    
    if not m1 and not m2: 
        flash('You can only chat with confirmed matches.', 'error')
        return redirect('/')
    return render_template('chat.html', partner=partner, me_id=me_id)

@app.route('/api/send_message', methods=['POST'])
def send_message():
    data = request.json
    new_msg = Message(sender_id=session['user_id'], receiver_id=data['receiver_id'], content=data['content'])
    db.session.add(new_msg)
    db.session.commit()
    return jsonify({'status': 'sent'})

@app.route('/api/get_messages/<int:partner_id>')
def get_messages(partner_id):
    me_id = session['user_id']
    messages = Message.query.filter(
        ((Message.sender_id == me_id) & (Message.receiver_id == partner_id)) |
        ((Message.sender_id == partner_id) & (Message.receiver_id == me_id))
    ).order_by(Message.timestamp.asc()).all()
    msgs_json = [{'sender': m.sender_id, 'content': m.content, 'time': m.timestamp.strftime('%H:%M')} for m in messages]
    return jsonify(msgs_json)

@app.route('/admin/reset_password', methods=['POST'])
def admin_reset_password():
    if 'user_id' not in session: return redirect('/login')
    me = User.query.get(session['user_id'])
    if not me.is_admin: return "Access Denied"
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')
    user = User.query.get(user_id)
    if user:
        user.password = new_password
        Report.query.filter_by(reported_id=user_id, reason="PASSWORD RESET REQUEST").delete()
        db.session.commit()
        flash(f'Password for {user.name} has been reset.', 'success')
    return redirect('/admin')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin').first():
            db.session.add(User(name='Admin', email='admin', password='admin', is_admin=True, is_verified=True))
            db.session.commit()
    app.run(debug=True)
