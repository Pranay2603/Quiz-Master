import json
import datetime
import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import click

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATABASE = 'quiz_master.db'

def tojson(value):
    return json.dumps(value)

app.jinja_env.filters['tojson'] = tojson

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    db.close()

@click.command('init-db')
def init_db_command():
    """Initialize the database and insert test data."""
    init_db()
    insert_test_data() # Call insert_test_data() after creating tables
    print('Initialized the database and inserted test data.')

with app.app_context():
    print("Initializing database and creating tables...") # Added for debugging
    # Create the database and the admin and user tables if they don't exist
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # You can add the initial admin user here if you want
    cursor.execute("INSERT OR IGNORE INTO admin (username, password) VALUES (?, ?)", ('admin', generate_password_hash('password')))

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT,
            qualification TEXT,
            dob TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subject (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chapter (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            FOREIGN KEY (subject_id) REFERENCES subject (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS question (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chapter_id INTEGER NOT NULL,
            question_text TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT,
            option_d TEXT,
            correct_option TEXT NOT NULL,
            FOREIGN KEY (chapter_id) REFERENCES chapter (id)
        )
    ''')

    db.commit()
    db.close()

# Add the insert_test_data() function here, before any routes
def insert_test_data():
    conn = get_db()
    cursor = conn.cursor()

    # Check if the scores table is empty
    cursor.execute("SELECT COUNT(*) FROM scores")
    count = cursor.fetchone()[0]

    if count == 0:
        # Check if the scores table exists (just in case)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scores'")
        table_exists = cursor.fetchone()

        if table_exists:
            # Insert test data
            cursor.execute("""
                INSERT INTO scores (quiz_id, user_id, time_stamp_of_attempt, total_scored)
                VALUES (1, 1, '2024-03-29 10:00:00', 80),
                       (1, 2, '2024-03-29 10:15:00', 90),
                       (2, 1, '2024-03-29 10:30:00', 70),
                       (2, 2, '2024-03-29 10:45:00', 85)
            """)
            conn.commit()

    conn.close()


@app.route("/")
def hello_world():
    return render_template('index.html')

@app.route('/register', methods=['GET'])
def register_form():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_user():
    username = request.form.get('username')
    password = request.form.get('password')
    full_name = request.form.get('full_name')
    qualification = request.form.get('qualification')
    dob = request.form.get('dob')

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('register_form'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Hash the password for security
    hashed_password = generate_password_hash(password)

    try:
        cursor.execute("INSERT INTO user (username, password, full_name, qualification, dob) VALUES (?, ?, ?, ?, ?)",
                       (username, hashed_password, full_name, qualification, dob))
        conn.commit()
        flash('Registration successful! You can now login.', 'success')
        return redirect(url_for('register_form'))
    except sqlite3.IntegrityError:
        flash('Username already exists. Please choose a different username.', 'error')
        return redirect(url_for('register_form'))
    finally:
        conn.close()

@app.route('/login', methods=['GET'])
def login_form():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_user():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('login_form'))

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Check for admin login
    if username == 'admin':
        cursor.execute("SELECT password FROM admin WHERE username = ?", (username,))
        admin_data = cursor.fetchone()
        conn.close()
        if admin_data and check_password_hash(admin_data['password'], password):
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard')) # Redirect to admin dashboard
        else:
            flash('Invalid admin credentials.', 'error')
            return redirect(url_for('login_form'))
    else:
        # Check for regular user login
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            flash('Login successful!', 'success')
            session['user_id'] = user['id']  # Store user ID in session
            return redirect(url_for('user_quizzes'))  # Redirect to user quizzes page
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login_form'))

@app.route('/admin/dashboard')
def admin_dashboard():
    conn = get_db()
    cursor = conn.cursor()

    # Search functionality
    search_users = request.args.get('search_users')
    search_subjects = request.args.get('search_subjects')
    search_quizzes = request.args.get('search_quizzes')

    if search_users:
        cursor.execute("SELECT * FROM user WHERE username LIKE ? OR full_name LIKE ?", ('%' + search_users + '%', '%' + search_users + '%')) # Corrected line
        users = cursor.fetchall()
    else:
        cursor.execute("SELECT * FROM user ORDER BY id ASC") # Modified line
        users = cursor.fetchall()

    if search_subjects:
        cursor.execute("SELECT * FROM subject WHERE name LIKE ?", ('%' + search_subjects + '%',))
        subjects = cursor.fetchall()
    else:
        cursor.execute("SELECT * FROM subject")
        subjects = cursor.fetchall()

    if search_quizzes:
        cursor.execute("SELECT * FROM quiz WHERE name LIKE ?", ('%' + search_quizzes + '%',))
        quizzes = cursor.fetchall()
    else:
        cursor.execute("SELECT * FROM quiz")
        quizzes = cursor.fetchall()

    # Get counts (as before)
    cursor.execute("SELECT COUNT(*) FROM user")
    user_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM subject")
    subject_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM quiz")
    quiz_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM question")
    question_count = cursor.fetchone()[0]

    # Get average quiz scores (as before)
    cursor.execute("""
        SELECT quiz.id, AVG(scores.total_scored)
        FROM quiz
        JOIN scores ON quiz.id = scores.quiz_id
        GROUP BY quiz.id
    """)
    quiz_scores = cursor.fetchall()
    quiz_scores = [dict(row) for row in quiz_scores]

    conn.close()
    print('quiz_scores from Flask:', quiz_scores)
    return render_template('admin_dashboard.html', user_count=user_count, subject_count=subject_count, quiz_count=quiz_count, question_count=question_count, quiz_scores=quiz_scores, users=users, subjects=subjects, quizzes=quizzes)

@app.route('/admin/subjects')
def admin_subjects():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description FROM subject")
    subjects = cursor.fetchall()
    conn.close()
    return render_template('admin_subjects.html', subjects=subjects)

@app.route('/admin/add_subject', methods=['GET'])
def admin_add_subject_form():
    return render_template('admin_add_subject.html')

@app.route('/admin/add_subject', methods=['POST'])
def admin_add_subject():
    name = request.form.get('name')
    description = request.form.get('description')

    if not name:
        flash('Subject name is required.', 'error')
        return redirect(url_for('admin_add_subject_form'))

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO subject (name, description) VALUES (?, ?)", (name, description))
        conn.commit()
        flash(f'Subject "{name}" added successfully!', 'success')
        return redirect(url_for('admin_subjects'))
    except sqlite3.IntegrityError:
        flash(f'Subject "{name}" already exists.', 'error')
        return redirect(url_for('admin_add_subject_form'))
    finally:
        conn.close()

@app.route('/admin/edit_subject/<int:id>', methods=['GET'])
def admin_edit_subject_form(id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description FROM subject WHERE id = ?", (id,))
    subject = cursor.fetchone()
    conn.close()
    if subject:
        return render_template('admin_edit_subject.html', subject=subject)
    else:
        flash('Subject not found.', 'error')
        return redirect(url_for('admin_subjects'))    

@app.route('/admin/edit_subject/<int:id>', methods=['POST'])
def admin_edit_subject(id):
    name = request.form.get('name')
    description = request.form.get('description')

    if not name:
        flash('Subject name is required.', 'error')
        return redirect(url_for('admin_edit_subject_form', id=id))

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE subject SET name = ?, description = ? WHERE id = ?", (name, description, id))
        conn.commit()
        flash(f'Subject "{name}" updated successfully!', 'success')
        return redirect(url_for('admin_subjects'))
    except sqlite3.IntegrityError:
        flash(f'Subject "{name}" already exists.', 'error')
        return redirect(url_for('admin_edit_subject_form', id=id))
    finally:
        conn.close()   

@app.route('/admin/delete_subject/<int:id>')
def admin_delete_subject(id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM subject WHERE id = ?", (id,))   
        conn.commit()
        flash('Subject deleted successfully!', 'success')
    except sqlite3.Error as e:
        conn.rollback()
        flash(f'Error deleting subject: {e}', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin_subjects'))

@app.route('/admin/subjects/<int:subject_id>/chapters')
def admin_chapters(subject_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description FROM subject WHERE id = ?", (subject_id,))
    subject = cursor.fetchone()
    if not subject:
        conn.close()
        flash('Subject not found.', 'error')
        return redirect(url_for('admin_subjects'))

    cursor.execute("SELECT id, name, description FROM chapter WHERE subject_id = ?", (subject_id,))
    chapters = cursor.fetchall()
    conn.close()
    return render_template('admin_chapters.html', subject=subject, chapters=chapters)

@app.route('/admin/add_chapter/<int:subject_id>', methods=['GET'])
def admin_add_chapter_form(subject_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM subject WHERE id = ?", (subject_id,))
    subject = cursor.fetchone()
    conn.close()
    if subject:
        return render_template('admin_add_chapter.html', subject=subject)
    else:
        flash('Subject not found.', 'error')
        return redirect(url_for('admin_subjects'))

@app.route('/admin/add_chapter/<int:subject_id>', methods=['POST'])
def admin_add_chapter(subject_id):
    name = request.form.get('name')
    description = request.form.get('description')

    if not name:
        flash('Chapter name is required.', 'error')
        return redirect(url_for('admin_add_chapter_form', subject_id=subject_id))

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO chapter (subject_id, name, description) VALUES (?, ?, ?)", (subject_id, name, description))
        conn.commit()
        flash(f'Chapter "{name}" added successfully!', 'success')
        return redirect(url_for('admin_chapters', subject_id=subject_id))
    except sqlite3.IntegrityError:
        flash(f'Chapter "{name}" already exists for this subject.', 'error')
        return redirect(url_for('admin_add_chapter_form', subject_id=subject_id))
    finally:
        conn.close()

import os
from flask import render_template_string

import os
from flask import render_template_string

@app.route('/admin/edit_chapter/<int:chapter_id>', methods=['GET', 'POST'])
def edit_chapter(chapter_id):
    conn = get_db()
    cursor = conn.cursor()

    chapter = cursor.execute("SELECT * FROM chapter WHERE id = ?", (chapter_id,)).fetchone()

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        cursor.execute("UPDATE chapter SET name = ?, description = ? WHERE id = ?", (name, description, chapter_id))
        conn.commit()
        conn.close()
        return redirect(url_for('admin_subjects', subject_id=chapter['subject_id']))

    template_path = os.path.join(app.root_path, 'templates', 'admin_edit_chapter.html') # change here
    template_content = open(template_path).read()
    rendered_template = render_template_string(template_content, chapter=chapter)
    conn.close()
    return rendered_template
    
@app.route('/admin/delete_chapter/<int:chapter_id>')
def admin_delete_chapter(chapter_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Get the subject_id before deleting to redirect back correctly
        cursor.execute("SELECT subject_id FROM chapter WHERE id = ?", (chapter_id,))
        chapter_info = cursor.fetchone()
        if chapter_info:
            subject_id = chapter_info[0]
            cursor.execute("DELETE FROM chapter WHERE id = ?", (chapter_id,))
            conn.commit()
            flash('Chapter deleted successfully!', 'success')
            return redirect(url_for('admin_chapters', subject_id=subject_id))
        else:
            flash('Chapter not found.', 'error')
            return redirect(url_for('admin_subjects'))
    except sqlite3.Error as e:
        conn.rollback()
        flash(f'Error deleting chapter: {e}', 'error')
        return redirect(url_for('admin_chapters', subject_id=subject_id if chapter_info else 0)) # Fallback
    finally:
        conn.close()

@app.route('/admin/chapters/<int:chapter_id>/questions')
def admin_questions(chapter_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, subject_id FROM chapter WHERE id = ?", (chapter_id,))
    chapter = cursor.fetchone()
    if not chapter:
        conn.close()
        flash('Chapter not found.', 'error')
        return redirect(url_for('admin_subjects'))

    cursor.execute("SELECT id, question_text, option_a, option_b, option_c, option_d, correct_option FROM question WHERE chapter_id = ?", (chapter_id,))
    questions = cursor.fetchall()
    print("Questions:", questions) # Add this line
    conn.close()
    return render_template('admin_questions.html', chapter=chapter, questions=questions)

@app.route('/admin/add_question/<int:chapter_id>', methods=['GET'])
def admin_add_question_form(chapter_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM chapter WHERE id = ?", (chapter_id,))
    chapter = cursor.fetchone()
    conn.close()
    if chapter:
        return render_template('admin_add_question.html', chapter=chapter)
    else:
        flash('Chapter not found.', 'error')
        return redirect(url_for('admin_subjects')) # Or a more appropriate redirect
    
@app.route('/admin/add_question/<int:chapter_id>', methods=['POST'])
def admin_add_question(chapter_id):
    question_text = request.form.get('question_text')
    option_a = request.form.get('option_a')
    option_b = request.form.get('option_b')
    option_c = request.form.get('option_c')
    option_d = request.form.get('option_d')
    correct_option = request.form.get('correct_option')

    if not question_text or not option_a or not option_b or not correct_option:
        flash('All question details are required.', 'error')
        return redirect(url_for('admin_add_question_form', chapter_id=chapter_id))

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO question (chapter_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (chapter_id, question_text, option_a, option_b, option_c, option_d, correct_option))
        conn.commit()
        flash('Question added successfully!', 'success')
        return redirect(url_for('admin_questions', chapter_id=chapter_id))
    except sqlite3.Error as e:
        conn.rollback()
        flash(f'Error adding question: {e}', 'error')
        return redirect(url_for('admin_add_question_form', chapter_id=chapter_id))
    finally:
        conn.close() #DOUBTTTT

@app.route('/admin/edit_question/<int:question_id>', methods=['GET'])
def admin_edit_question_form(question_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, question_text, option_a, option_b, option_c, option_d, correct_option, chapter_id FROM question WHERE id = ?", (question_id,))
    question = cursor.fetchone()
    conn.close()
    if question:
        return render_template('admin_edit_question.html', question=question)
    else:
        flash('Question not found.', 'error')
        return redirect(url_for('admin_questions', chapter_id=question['chapter_id']))  # Redirect to questions of the chapter
    
import logging
import traceback

@app.route('/admin/delete_question/<int:question_id>')
def admin_delete_question(question_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Fetch chapter_id before deleting
        cursor.execute("SELECT chapter_id FROM question WHERE id = ?", (question_id,))
        row = cursor.fetchone()

        if row:
            chapter_id = row['chapter_id']

            cursor.execute("DELETE FROM question WHERE id = ?", (question_id,))
            conn.commit()
            flash('Question deleted successfully!', 'success')
        else:
            flash('Question not found.', 'error')
            return redirect(url_for('admin_subjects')) # Or another suitable redirect

    except sqlite3.Error as e:
        conn.rollback()
        logging.error(f"Database error deleting question: {e}")
        logging.error(traceback.format_exc()) # Log the full traceback
        flash(f'Error deleting question: {e}', 'error')
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        logging.error(traceback.format_exc()) # Log the full traceback
        flash('An unexpected error occurred.', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin_questions', chapter_id=chapter_id))  # Redirect to questions of the chapter

@app.route('/admin/edit_question/<int:question_id>', methods=['POST'])
def admin_edit_question(question_id):
    question_text = request.form.get('question_text')
    option_a = request.form.get('option_a')
    option_b = request.form.get('option_b')
    option_c = request.form.get('option_c')
    option_d = request.form.get('option_d')
    correct_option = request.form.get('correct_option')

    if not question_text or not option_a or not option_b or not correct_option:
        flash('All question details are required.', 'error')
        return redirect(url_for('admin_edit_question_form', question_id=question_id))

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE question SET question_text = ?, option_a = ?, option_b = ?, option_c = ?, option_d = ?, correct_option = ? WHERE id = ?",
                       (question_text, option_a, option_b, option_c, option_d, correct_option, question_id))
        conn.commit()
        flash('Question updated successfully!', 'success')

        # Fetch chapter_id before redirecting
        cursor.execute("SELECT chapter_id FROM question WHERE id = ?", (question_id,))
        row = cursor.fetchone()
        if row:
            chapter_id = row['chapter_id']
            return redirect(url_for('admin_questions', chapter_id=chapter_id))  # Redirect to questions of the chapter
        else:
            flash('Question not found.', 'error')
            return redirect(url_for('admin_subjects')) # Or another suitable redirect

        # Add this line to force an exception:
        raise Exception("Forced exception for debugging")

    except sqlite3.Error as e:
        conn.rollback()
        flash(f'Error updating question: {e}', 'error')
        return redirect(url_for('admin_edit_question_form', question_id=question_id))
    finally:
        conn.close()

@app.route('/admin/add_quiz', methods=['GET'])
def admin_add_quiz_form():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, question_text FROM question")
    questions = cursor.fetchall()
    conn.close()
    return render_template('admin_add_quiz.html', questions=questions)

@app.route('/admin/quizzes')
def admin_quizzes():
    conn = get_db()
    cursor = conn.cursor()

    search_quizzes = request.args.get('search_quizzes')

    if search_quizzes:
        cursor.execute("SELECT id, name, description, date, duration FROM quiz WHERE name LIKE ?", ('%' + search_quizzes + '%',))
        quizzes = cursor.fetchall()
    else:
        cursor.execute("SELECT id, name, description, date, duration FROM quiz")
        quizzes = cursor.fetchall()

    conn.close()
    return render_template('admin_quizzes.html', quizzes=quizzes)

@app.route('/admin/add_quiz', methods=['POST'])
def admin_add_quiz():
    name = request.form['name']
    description = request.form['description']
    date = request.form['date']
    duration = request.form['duration']

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO quiz (name, description, date, duration) VALUES (?, ?, ?, ?)", (name, description, date, duration))
        conn.commit()
        flash('Quiz added successfully!', 'success')
        return redirect(url_for('admin_quizzes'))
    except sqlite3.Error as e:
        conn.rollback()
        flash(f'Error adding quiz: {e}', 'error')
    finally:
        conn.close()

    return render_template('admin_add_quiz.html')

@app.route('/admin/edit_quiz/<int:id>', methods=['GET'])
def admin_edit_quiz_form(id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description, date, duration FROM quiz WHERE id = ?", (id,))
    quiz = cursor.fetchone()
    cursor.execute("SELECT id, question_text FROM question")
    questions = cursor.fetchall()
    cursor.execute("SELECT question_id FROM quiz_question WHERE quiz_id = ?", (id,))
    selected_questions = [row['question_id'] for row in cursor.fetchall()]
    conn.close()
    if quiz:
        return render_template('admin_edit_quiz.html', quiz=quiz, questions=questions, selected_questions=selected_questions)
    else:
        flash('Quiz not found.', 'error')
        return redirect(url_for('admin_quizzes'))
    
@app.route('/admin/delete_quiz/<int:id>')
def admin_delete_quiz(id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM quiz WHERE id = ?", (id,))
        conn.commit()
        flash('Quiz deleted successfully!', 'success')
    except sqlite3.Error as e:
        conn.rollback()
        flash(f'Error deleting quiz: {e}', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin_quizzes'))

@app.route('/admin/quizzes/<int:id>/questions')
def admin_quiz_questions(id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT q.question_text FROM question q JOIN quiz_question qq ON q.id = qq.question_id WHERE qq.quiz_id = ?", (id,))
    questions = cursor.fetchall()
    conn.close()
    return render_template('admin_quiz_questions.html', questions=questions)

@app.route('/admin/edit_quiz/<int:id>', methods=['POST'])
def admin_edit_quiz(id):
    name = request.form['name']
    description = request.form['description']
    date = request.form['date']
    duration = request.form['duration']
    question_ids = request.form.getlist('questions')  # Get list of selected question IDs

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE quiz SET name = ?, description = ?, date = ?, duration = ? WHERE id = ?", (name, description, date, duration, id))

        # Delete existing quiz-question associations
        cursor.execute("DELETE FROM quiz_question WHERE quiz_id = ?", (id,))

        # Insert new quiz-question associations
        if question_ids:
            for question_id in question_ids:
                cursor.execute("INSERT INTO quiz_question (quiz_id, question_id) VALUES (?, ?)", (id, question_id))

        conn.commit()
        flash('Quiz updated successfully!', 'success')
        return redirect(url_for('admin_quizzes'))
    except sqlite3.Error as e:
        conn.rollback()
        flash(f'Error updating quiz: {e}', 'error')
    finally:
        conn.close()

    return render_template('admin_edit_quiz.html')

@app.route('/user/quizzes')
def user_quizzes():
    if 'user_id' not in session:
        flash('Please log in to view quizzes.', 'error')
        return redirect(url_for('login_form'))

    user_id = session['user_id']

    conn = get_db()
    cursor = conn.cursor()

    # Retrieve past quiz attempts for the current user
    cursor.execute("""
        SELECT quiz.name, scores.time_stamp_of_attempt, scores.total_scored
        FROM scores
        JOIN quiz ON scores.quiz_id = quiz.id
        WHERE scores.user_id = ?
    """, (user_id,))
    past_attempts = cursor.fetchall()

    # Retrieve all quizzes for the user to take
    cursor.execute("SELECT id, name, description, date, duration FROM quiz")
    quizzes = cursor.fetchall()

    conn.close()
    return render_template('user_quizzes.html', quizzes=quizzes, past_attempts=past_attempts)

@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_form'))

    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()

    # Get user information
    cursor.execute("SELECT full_name FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    # Get past quiz attempts and convert to dictionaries
    cursor.execute("""
        SELECT quiz.name, scores.time_stamp_of_attempt, scores.total_scored
        FROM scores
        JOIN quiz ON scores.quiz_id = quiz.id
        WHERE scores.user_id = ?
    """, (user_id,))
    past_attempts_rows = cursor.fetchall()  # Fetch as rows
    past_attempts = [dict(row) for row in past_attempts_rows]  # Convert to dictionaries

    conn.close()

    return render_template('user_dashboard.html', user=user, past_attempts=past_attempts)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login_form'))

@app.route('/admin/questions/<int:question_id>/add_option', methods=['GET', 'POST'])
def admin_add_option(question_id):
    if request.method == 'POST':
        option_text = request.form['option_text']
        is_correct = request.form['is_correct']

        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO options (question_id, option_text, is_correct) VALUES (?, ?, ?)", (question_id, option_text, is_correct))
            conn.commit()
            flash('Option added successfully!', 'success')
            return redirect(url_for('admin_questions', chapter_id=request.args.get('chapter_id')))
        except sqlite3.Error as e:
            conn.rollback()
            flash(f'Error adding option: {e}', 'error')
        finally:
            conn.close()

    return render_template('admin_add_option.html', question_id=question_id, chapter_id=request.args.get('chapter_id'))

@app.route('/user/quizzes/<int:id>/take')
def take_quiz(id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description, date, duration FROM quiz WHERE id = ?", (id,))
    quiz = cursor.fetchone()
    cursor.execute("SELECT q.id, q.question_text FROM question q JOIN quiz_question qq ON q.id = qq.question_id WHERE qq.quiz_id = ?", (id,))
    questions = cursor.fetchall()

    # Convert sqlite3.Row objects to dictionaries
    questions = [dict(row) for row in questions]

    for question in questions:
        cursor.execute("SELECT id, option_text FROM options WHERE question_id = ?", (question['id'],))
        options = cursor.fetchall()
        question['options'] = [dict(row) for row in options]  # Convert options to dictionaries

    conn.close()
    return render_template('take_quiz.html', quiz=quiz, questions=questions)

@app.route('/user/quizzes/<int:id>/submit', methods=['POST'])
def submit_quiz(id):
    answers = request.form.to_dict(flat=False)
    answers = {int(k.split('[')[1].split(']')[0]): int(v[0]) for k, v in answers.items() if k.startswith('answers')}

    conn = get_db()
    cursor = conn.cursor()

    score = 0
    for question_id, selected_option_id in answers.items():
        cursor.execute("SELECT is_correct FROM options WHERE id = ?", (selected_option_id,))
        is_correct = cursor.fetchone()['is_correct']
        if is_correct == 1:
            score += 1

    user_id = session.get('user_id')  # Get user_id from session

    if user_id:
        try:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Get current timestamp
            cursor.execute("INSERT INTO scores (quiz_id, user_id, total_scored, time_stamp_of_attempt) VALUES (?, ?, ?, ?)", (id, user_id, score, timestamp))
            conn.commit()
            print(f"Quiz score inserted: quiz_id={id}, user_id={user_id}, score={score}, timestamp={timestamp}")  # Debugging
        except sqlite3.Error as e:
            conn.rollback()
            print(f"Database error inserting score: {e}")  # Debugging
        finally:
            conn.close()
    else:
        print("User ID not found in session.")  # Debugging
        conn.close()

    return render_template('quiz_results.html', score=score, total_questions=len(answers))

@app.route('/admin/users')
def admin_users():  
    conn = get_db()
    cursor = conn.cursor()

    search_users = request.args.get('search_users')

    if search_users:
        cursor.execute("SELECT id, username, full_name, qualification, dob FROM user WHERE username LIKE ?", ('%' + search_users + '%',))
        users = cursor.fetchall()
    else:
        cursor.execute("SELECT id, username, full_name, qualification, dob FROM user")
        users = cursor.fetchall()

    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET'])
def admin_edit_user_form(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, qualification, dob FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return render_template('admin_edit_user.html', user=user)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/users/edit/<int:user_id>', methods=['POST'])
def admin_edit_user(user_id):
    username = request.form['username']
    full_name = request.form['full_name']
    qualification = request.form['qualification']
    dob = request.form['dob']

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE user SET username = ?, full_name = ?, qualification = ?, dob = ? WHERE id = ?",
                   (username, full_name, qualification, dob, user_id))
    conn.commit()
    conn.close()
    flash('User updated successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>')
def admin_delete_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_users'))




if __name__ == "__main__":
    app.run(debug=True, port=8000)

def init_app(app):
    app.cli.add_command(init_db_command)

init_app(app)

@app.template_filter('tojson')
def tojson_filter(value):
    return json.dumps(value)