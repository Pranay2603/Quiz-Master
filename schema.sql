CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quiz (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    date TEXT,
    duration INTEGER -- Duration in minutes
);

CREATE TABLE IF NOT EXISTS quiz_question (
    quiz_id INTEGER NOT NULL,
    question_id INTEGER NOT NULL,
    PRIMARY KEY (quiz_id, question_id),
    FOREIGN KEY (quiz_id) REFERENCES quiz (id),
    FOREIGN KEY (question_id) REFERENCES question (id)
);

CREATE TABLE IF NOT EXISTS options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER,
    option_text TEXT,
    is_correct INTEGER,
    FOREIGN KEY (question_id) REFERENCES question (id)
);


CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quiz_id INTEGER,
    user_id INTEGER,
    time_stamp_of_attempt TEXT,
    total_scored INTEGER,
    FOREIGN KEY (quiz_id) REFERENCES quiz (id),
    FOREIGN KEY (user_id) REFERENCES user (id)
);