from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import uuid
import requests
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secure secret key

# Database setup
DATABASE = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    # Create metrics table with google_sheet_url
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            metric_name TEXT NOT NULL,
            csv_data TEXT,
            google_sheet_url TEXT,
            switch_axes INTEGER DEFAULT 0,
            chart_type TEXT DEFAULT 'bar',
            position INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    # Create shared_dashboards table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_dashboards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            share_id TEXT UNIQUE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    # Initialize position for existing metrics if not set
    cursor.execute('SELECT COUNT(*) FROM metrics WHERE position > 0')
    count = cursor.fetchone()[0]
    if count == 0:
        cursor.execute('UPDATE metrics SET position = id')
        conn.commit()
    conn.close()

init_db()

# Helper function to extract sheet_id and gid from Google Sheets URL
def parse_google_sheet_url(url):
    """
    Extracts the sheet ID and gid from a Google Sheets URL.
    Returns a tuple (sheet_id, gid) if successful, else (None, None).
    """
    # Regex to match Google Sheets URLs
    regex = r"https://docs\.google\.com/spreadsheets/d/([a-zA-Z0-9-_]+)(?:/.*)?(?:#gid=(\d+))?"
    match = re.match(regex, url)
    if match:
        sheet_id = match.group(1)
        gid = match.group(2) if match.group(2) else '0'
        return sheet_id, gid
    return None, None

# Routes
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Handle login
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('index'))
    
    return render_template('index.html', login=True)

@app.route('/register', methods=['POST'])
def register():
    # Handle user registration
    username = request.form['username']
    password = request.form['password']
    
    if not username or not password:
        flash('Username and password are required')
        return redirect(url_for('index'))
    
    password_hash = generate_password_hash(password)
    
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                     (username, password_hash))
        conn.commit()
        conn.close()
        flash('Registration successful. Please log in.')
    except sqlite3.IntegrityError:
        flash('Username already exists')
    
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    metrics = conn.execute('SELECT * FROM metrics WHERE user_id = ? ORDER BY position ASC', (user_id,)).fetchall()
    conn.close()
    
    return render_template('index.html', login=False, metrics=metrics, username=session.get('username'), shared=False)

@app.route('/share_dashboard', methods=['POST'])
def share_dashboard():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    share_id = str(uuid.uuid4())
    
    conn = get_db_connection()
    conn.execute('INSERT INTO shared_dashboards (user_id, share_id) VALUES (?, ?)', (user_id, share_id))
    conn.commit()
    conn.close()
    
    share_url = request.host_url + 'share/' + share_id
    return jsonify({'share_url': share_url})

@app.route('/share/<share_id>')
def shared_dashboard(share_id):
    conn = get_db_connection()
    shared = conn.execute('SELECT * FROM shared_dashboards WHERE share_id = ?', (share_id,)).fetchone()
    if not shared:
        conn.close()
        flash('Invalid share link')
        return redirect(url_for('index'))
    
    user_id = shared['user_id']
    metrics = conn.execute('SELECT * FROM metrics WHERE user_id = ? ORDER BY position ASC', (user_id,)).fetchall()
    conn.close()
    
    return render_template('index.html', login=False, metrics=metrics, username=None, shared=True, share_id=share_id)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    metric_name = request.form.get('metric_name', 'Unnamed Metric').strip()
    csv_file = request.files.get('csv_file')
    google_sheet_url = request.form.get('google_sheet_url', '').strip()
    
    if not metric_name:
        flash('Metric name is required')
        return redirect(url_for('dashboard'))
    
    if not csv_file and not google_sheet_url:
        flash('Either a CSV file or a Google Sheets URL must be provided')
        return redirect(url_for('dashboard'))
    
    user_id = session['user_id']
    conn = get_db_connection()
    
    # Determine the next position
    last_metric = conn.execute('SELECT MAX(position) as max_pos FROM metrics WHERE user_id = ?', (user_id,)).fetchone()
    next_position = (last_metric['max_pos'] or 0) + 1
    
    if google_sheet_url:
        # Validate Google Sheets URL
        sheet_id, gid = parse_google_sheet_url(google_sheet_url)
        if not sheet_id:
            flash('Invalid Google Sheets URL')
            conn.close()
            return redirect(url_for('dashboard'))
        # Insert metric with Google Sheets URL
        conn.execute('INSERT INTO metrics (user_id, metric_name, google_sheet_url, position) VALUES (?, ?, ?, ?)',
                     (user_id, metric_name, google_sheet_url, next_position))
        conn.commit()
        conn.close()
        flash('Metric added successfully from Google Sheets')
        return redirect(url_for('dashboard'))
    elif csv_file:
        if csv_file.filename == '':
            flash('No selected file')
            conn.close()
            return redirect(url_for('dashboard'))
        
        if csv_file and allowed_file(csv_file.filename):
            csv_data = csv_file.read().decode('utf-8')
            conn.execute('INSERT INTO metrics (user_id, metric_name, csv_data, position) VALUES (?, ?, ?, ?)',
                         (user_id, metric_name, csv_data, next_position))
            conn.commit()
            conn.close()
            flash('Metric uploaded successfully')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type. Only CSV files are allowed.')
            conn.close()
            return redirect(url_for('dashboard'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'csv'

@app.route('/data/<int:metric_id>')
def data(metric_id):
    if 'user_id' not in session:
        # Allow access if it's a shared dashboard
        share_id = request.args.get('share_id')
        if not share_id:
            return jsonify({'error': 'Unauthorized'}), 401
        conn = get_db_connection()
        shared = conn.execute('SELECT * FROM shared_dashboards WHERE share_id = ?', (share_id,)).fetchone()
        conn.close()
        if not shared:
            return jsonify({'error': 'Invalid share link'}), 404
        user_id = shared['user_id']
    else:
        user_id = session['user_id']
    
    conn = get_db_connection()
    metric = conn.execute('SELECT * FROM metrics WHERE id = ? AND user_id = ?', (metric_id, user_id)).fetchone()
    conn.close()
    
    if metric:
        if metric['google_sheet_url']:
            # Fetch data from Google Sheets
            sheet_id, gid = parse_google_sheet_url(metric['google_sheet_url'])
            if not sheet_id:
                return jsonify({'error': 'Invalid Google Sheets URL'}), 400
            csv_export_url = f'https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid={gid}'
            try:
                response = requests.get(csv_export_url)
                response.raise_for_status()
                csv_content = response.text
            except requests.RequestException as e:
                return jsonify({'error': f'Failed to fetch Google Sheets data: {str(e)}'}), 500
        else:
            csv_content = metric['csv_data']
        
        switch_axes = metric['switch_axes']
        chart_type = metric['chart_type']
        # Simple CSV parsing (assumes two columns: label, value)
        lines = csv_content.strip().split('\n')
        labels = []
        values = []
        for line in lines:
            parts = line.split(',')
            if len(parts) >= 2:
                labels.append(parts[0].strip())
                try:
                    values.append(float(parts[1].strip()))
                except ValueError:
                    values.append(0)
        if switch_axes:
            labels, values = values, labels  # Swap axes
        return jsonify({
            'labels': labels,
            'values': values,
            'metric_name': metric['metric_name'],
            'switch_axes': switch_axes,
            'chart_type': chart_type
        })
    else:
        return jsonify({'error': 'Metric not found'}), 404

@app.route('/update_axes', methods=['POST'])
def update_axes():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    metric_id = data.get('metric_id')
    switch_axes = data.get('switch_axes')
    
    if metric_id is None or switch_axes is None:
        return jsonify({'error': 'Invalid data'}), 400
    
    conn = get_db_connection()
    metric = conn.execute('SELECT * FROM metrics WHERE id = ? AND user_id = ?', (metric_id, session['user_id'])).fetchone()
    if not metric:
        conn.close()
        return jsonify({'error': 'Metric not found'}), 404
    
    conn.execute('UPDATE metrics SET switch_axes = ? WHERE id = ?', (switch_axes, metric_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/update_chart_type', methods=['POST'])
def update_chart_type():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    metric_id = data.get('metric_id')
    chart_type = data.get('chart_type')
    
    if metric_id is None or not chart_type:
        return jsonify({'error': 'Invalid data'}), 400
    
    allowed_chart_types = ['bar', 'line', 'pie', 'doughnut', 'radar', 'polarArea']
    if chart_type not in allowed_chart_types:
        return jsonify({'error': 'Invalid chart type'}), 400
    
    conn = get_db_connection()
    metric = conn.execute('SELECT * FROM metrics WHERE id = ? AND user_id = ?', (metric_id, session['user_id'])).fetchone()
    if not metric:
        conn.close()
        return jsonify({'error': 'Metric not found'}), 404
    
    conn.execute('UPDATE metrics SET chart_type = ? WHERE id = ?', (chart_type, metric_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/update_order', methods=['POST'])
def update_order():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    metric_order = data.get('metric_order')  # Expected to be a list of metric IDs in new order
    
    if not isinstance(metric_order, list):
        return jsonify({'error': 'Invalid data'}), 400
    
    conn = get_db_connection()
    for position, metric_id in enumerate(metric_order, start=1):
        conn.execute('UPDATE metrics SET position = ? WHERE id = ? AND user_id = ?', (position, metric_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    # Ensure the database file exists
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
