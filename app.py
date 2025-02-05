import os
import uuid
import trimesh
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tajny_klucz'  # W produkcji użyj bezpieczniejszego klucza
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Ustalona kolejność stanów projektu
PROJECT_STATES = [
    "wrzuć pliki",
    "wycena",
    "projekt",
    "ostateczna wycena",
    "miejsce w kolejce",
    "wydruk",
    "suszenie",
    "utwardzanie",
    "pakowanie",
    "wysyłka"
]

########################################
# MODELE
########################################

# Model konfiguracji – przechowuje globalne ustawienia
class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.String(64), nullable=False)

def get_config_value(key, default=None):
    config = Config.query.filter_by(key=key).first()
    if config:
        return config.value
    return default

def set_config_value(key, value):
    config = Config.query.filter_by(key=key).first()
    if not config:
        config = Config(key=key, value=str(value))
        db.session.add(config)
    else:
        config.value = str(value)
    db.session.commit()

def get_global_price():
    try:
        return float(get_config_value("PricePerML", 2.0))
    except:
        return 2.0

# Model użytkownika – role: 'client', 'business' lub 'admin'
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='client')  # domyślnie 'client'
    # Dla użytkowników biznesowych – opcjonalna wartość ich własnej ceny za ml
    my_price_per_ml = db.Column(db.Float, nullable=True)
    projects = db.relationship('Project', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Model projektu – dodano pola: name, quantity oraz order_comment
class Project(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(256), nullable=False)  # nazwa projektu
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    main_file_name = db.Column(db.String(256))
    main_file_path = db.Column(db.String(512))
    volume_ml = db.Column(db.Float)
    estimated_cost = db.Column(db.Float)
    final_cost = db.Column(db.Float, nullable=True)
    state = db.Column(db.String(50))
    quantity = db.Column(db.Integer, nullable=False, default=1)
    order_comment = db.Column(db.Text, nullable=True)
    files = db.relationship('ProjectFile', backref='project', lazy=True)
    state_logs = db.relationship('ProjectStateLog', backref='project', lazy=True)

# Model pliku projektu
class ProjectFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey('project.id'), nullable=False)
    filename = db.Column(db.String(256))
    file_path = db.Column(db.String(512))

# Model loga zmian stanu projektu
class ProjectStateLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.String(36), db.ForeignKey('project.id'), nullable=False)
    old_state = db.Column(db.String(50))
    new_state = db.Column(db.String(50))
    changed_by = db.Column(db.String(80))  # nazwa użytkownika dokonującego zmiany
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

########################################
# FUNKCJE POMOCNICZE
########################################

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'stl', 'obj'}

########################################
# ROUTY
########################################

# Główna trasa – przekierowanie do odpowiedniego dashboardu po zalogowaniu
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'business':
            return redirect(url_for('business_dashboard'))
        elif current_user.role == 'client':
            return redirect(url_for('client_dashboard'))
    return render_template("index.html")

# Dashboardy
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Brak dostępu do panelu administratora.")
        return redirect(url_for('index'))
    projects = Project.query.all()
    return render_template("admin_dashboard.html", projects=projects, global_price=get_global_price())

@app.route('/business/dashboard')
@login_required
def business_dashboard():
    if current_user.role != 'business':
        flash("Brak dostępu do panelu biznesowego.")
        return redirect(url_for('index'))
    projects = Project.query.all()
    return render_template("business_dashboard.html", projects=projects)

@app.route('/client/dashboard')
@login_required
def client_dashboard():
    if current_user.role != 'client':
        flash("Brak dostępu do panelu klienta.")
        return redirect(url_for('index'))
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template("client_dashboard.html", projects=projects)

# Rejestracja – przy rejestracji użytkownik wybiera rolę ('client' lub 'business')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")
        if role not in ['client', 'business']:
            flash("Nieprawidłowa rola użytkownika.")
            return redirect(url_for('register'))
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Użytkownik o takiej nazwie lub emailu już istnieje.")
            return redirect(url_for('register'))
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Rejestracja zakończona powodzeniem. Możesz się teraz zalogować.")
        return redirect(url_for('login'))
    return render_template("register.html")

# Logowanie – po zalogowaniu przekierowujemy do głównej trasy (która rozdziela dashboardy)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Zalogowano pomyślnie.")
            return redirect(url_for('index'))
        else:
            flash("Nieprawidłowe dane logowania.")
            return redirect(url_for('login'))
    return render_template("login.html")

# Wylogowanie
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Wylogowano.")
    return redirect(url_for('index'))

# Dashboard dla biznesu – umożliwiamy również aktualizację ceny "myPricePerML"
@app.route('/business/update_price', methods=['GET', 'POST'])
@login_required
def business_update_price():
    if current_user.role != 'business':
        flash("Brak dostępu.")
        return redirect(url_for('index'))
    if request.method == 'POST':
        new_price = request.form.get("my_price_per_ml")
        try:
            current_user.my_price_per_ml = float(new_price.replace(",", "."))
            db.session.commit()
            flash("Zaktualizowano Moja Cena za ml.")
        except ValueError:
            flash("Nieprawidłowa wartość ceny.")
        return redirect(url_for('business_dashboard'))
    return render_template("business_update_price.html", current_price=current_user.my_price_per_ml)

# Dashboard dla administratora – umożliwiamy aktualizację globalnej ceny PricePerML
@app.route('/admin/update_global_price', methods=['GET', 'POST'])
@login_required
def admin_update_global_price():
    if current_user.role != 'admin':
        flash("Brak dostępu.")
        return redirect(url_for('index'))
    if request.method == 'POST':
        new_price = request.form.get("global_price")
        try:
            new_price_val = float(new_price.replace(",", "."))
            set_config_value("PricePerML", new_price_val)
            flash("Global PricePerML zaktualizowany.")
        except ValueError:
            flash("Nieprawidłowa wartość ceny.")
        return redirect(url_for('admin_dashboard'))
    return render_template("admin_update_global_price.html", global_price=get_global_price())

# Upload projektu – uwzględnia również pola: quantity i order_comment
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        project_name = request.form.get("project_name")
        if not project_name:
            flash("Podaj nazwę projektu.")
            return redirect(request.url)
        try:
            quantity = int(request.form.get("quantity", 1))
        except ValueError:
            flash("Ilość musi być liczbą całkowitą.")
            return redirect(request.url)
        order_comment = request.form.get("order_comment")
        
        if 'files' not in request.files:
            flash("Brak plików w żądaniu.")
            return redirect(request.url)
        files = request.files.getlist('files')
        if not files or files[0].filename == '':
            flash("Nie wybrano żadnych plików.")
            return redirect(request.url)
        
        project_files = []
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4()) + "_" + filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                project_files.append((filename, file_path))
            else:
                flash("Niedozwolony typ pliku. Dozwolone są tylko .stl i .obj")
                return redirect(request.url)
        
        total_volume_mm3 = 0
        for fname, fpath in project_files:
            try:
                mesh = trimesh.load(fpath, force='mesh')
                total_volume_mm3 += mesh.volume
            except Exception as e:
                flash("Błąd przy obliczaniu objętości dla pliku " + fname + ": " + str(e))
                return redirect(request.url)
        volume_ml = total_volume_mm3 / 1000.0
        
        # Używamy globalnej ceny PricePerML
        global_price = get_global_price()
        estimated_cost = volume_ml * global_price * quantity

        project = Project(
            user_id=current_user.id,
            name=project_name,
            main_file_name=project_files[0][0],
            main_file_path=project_files[0][1],
            volume_ml=volume_ml,
            estimated_cost=estimated_cost,
            state="projekt",
            quantity=quantity,
            order_comment=order_comment
        )
        db.session.add(project)
        db.session.commit()
        for fname, fpath in project_files:
            pf = ProjectFile(project_id=project.id, filename=fname, file_path=fpath)
            db.session.add(pf)
        db.session.commit()
        flash(f"Projekt '{project_name}' utworzony. Łączna objętość: {volume_ml:.2f} ml, Wstępna wycena: {estimated_cost:.2f} PLN")
        if current_user.role == 'client':
            return redirect(url_for('client_dashboard'))
        elif current_user.role == 'business':
            return redirect(url_for('business_dashboard'))
        else:
            return redirect(url_for('admin_dashboard'))
    return render_template("upload.html")

# Widok szczegółów projektu dla klienta
@app.route('/client/project/<project_id>')
@login_required
def client_project_detail(project_id):
    if current_user.role != 'client':
        flash("Brak dostępu.")
        return redirect(url_for('index'))
    project = db.session.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        flash("Nie masz dostępu do tego projektu.")
        return redirect(url_for('client_dashboard'))
    logs = ProjectStateLog.query.filter_by(project_id=project.id).order_by(ProjectStateLog.timestamp.desc()).all()
    files = ProjectFile.query.filter_by(project_id=project.id).all()
    return render_template("client_project_detail.html", project=project, logs=logs, files=files)

# Widok szczegółów projektu dla biznesu
@app.route('/business/project/<project_id>', methods=['GET', 'POST'])
@login_required
def business_project_detail(project_id):
    if current_user.role != 'business':
        flash("Brak dostępu.")
        return redirect(url_for('index'))
    project = db.session.get(Project, project_id)
    if not project:
        flash("Nie znaleziono projektu.")
        return redirect(url_for('business_dashboard'))
    if request.method == 'POST':
        if 'next_state' in request.form:
            try:
                current_index = PROJECT_STATES.index(project.state)
                if current_index < len(PROJECT_STATES) - 1:
                    old_state = project.state
                    new_state = PROJECT_STATES[current_index + 1]
                    project.state = new_state
                    log = ProjectStateLog(
                        project_id=project.id,
                        old_state=old_state,
                        new_state=new_state,
                        changed_by=current_user.username
                    )
                    db.session.add(log)
                    db.session.commit()
                    flash("Stan projektu przesunięty do: " + new_state)
                else:
                    flash("Projekt jest już w ostatnim stanie.")
            except ValueError:
                flash("Nieznany stan projektu.")
            return redirect(url_for('business_project_detail', project_id=project.id))
        if 'prev_state' in request.form:
            try:
                current_index = PROJECT_STATES.index(project.state)
                if current_index > 0:
                    old_state = project.state
                    new_state = PROJECT_STATES[current_index - 1]
                    project.state = new_state
                    log = ProjectStateLog(
                        project_id=project.id,
                        old_state=old_state,
                        new_state=new_state,
                        changed_by=current_user.username
                    )
                    db.session.add(log)
                    db.session.commit()
                    flash("Stan projektu przesunięty do: " + new_state)
                else:
                    flash("Projekt jest już w pierwszym stanie.")
            except ValueError:
                flash("Nieznany stan projektu.")
            return redirect(url_for('business_project_detail', project_id=project.id))
        final_cost = request.form.get("final_cost")
        if final_cost:
            try:
                project.final_cost = float(final_cost.replace(",", "."))
                db.session.commit()
                flash("Zaktualizowano cenę ostateczną.")
            except ValueError:
                flash("Nieprawidłowa wartość ceny.")
            return redirect(url_for('business_project_detail', project_id=project.id))
    logs = ProjectStateLog.query.filter_by(project_id=project.id).order_by(ProjectStateLog.timestamp.desc()).all()
    files = ProjectFile.query.filter_by(project_id=project.id).all()
    global_price = get_global_price()
    return render_template("business_project_detail.html", project=project, logs=logs, files=files, global_price=global_price)
    
# Widok szczegółów projektu dla administratora
@app.route('/admin/project/<project_id>', methods=['GET', 'POST'])
@login_required
def admin_project_detail(project_id):
    if current_user.role != 'admin':
        flash("Brak dostępu.")
        return redirect(url_for('index'))
    project = db.session.get(Project, project_id)
    if not project:
        flash("Nie znaleziono projektu.")
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        if 'next_state' in request.form:
            try:
                current_index = PROJECT_STATES.index(project.state)
                if current_index < len(PROJECT_STATES) - 1:
                    old_state = project.state
                    new_state = PROJECT_STATES[current_index + 1]
                    project.state = new_state
                    log = ProjectStateLog(
                        project_id=project.id,
                        old_state=old_state,
                        new_state=new_state,
                        changed_by=current_user.username
                    )
                    db.session.add(log)
                    db.session.commit()
                    flash("Stan projektu przesunięty do: " + new_state)
                else:
                    flash("Projekt jest już w ostatnim stanie.")
            except ValueError:
                flash("Nieznany stan projektu.")
            return redirect(url_for('admin_project_detail', project_id=project.id))
        if 'prev_state' in request.form:
            try:
                current_index = PROJECT_STATES.index(project.state)
                if current_index > 0:
                    old_state = project.state
                    new_state = PROJECT_STATES[current_index - 1]
                    project.state = new_state
                    log = ProjectStateLog(
                        project_id=project.id,
                        old_state=old_state,
                        new_state=new_state,
                        changed_by=current_user.username
                    )
                    db.session.add(log)
                    db.session.commit()
                    flash("Stan projektu przesunięty do: " + new_state)
                else:
                    flash("Projekt jest już w pierwszym stanie.")
            except ValueError:
                flash("Nieznany stan projektu.")
            return redirect(url_for('admin_project_detail', project_id=project.id))
        final_cost = request.form.get("final_cost")
        if final_cost:
            try:
                project.final_cost = float(final_cost.replace(",", "."))
                db.session.commit()
                flash("Zaktualizowano cenę ostateczną.")
            except ValueError:
                flash("Nieprawidłowa wartość ceny.")
            return redirect(url_for('admin_project_detail', project_id=project.id))
    logs = ProjectStateLog.query.filter_by(project_id=project.id).order_by(ProjectStateLog.timestamp.desc()).all()
    files = ProjectFile.query.filter_by(project_id=project.id).all()
    return render_template("admin_project_detail.html", project=project, logs=logs, files=files)

########################################
# Trasa Download – pobieranie pliku
########################################

@app.route('/download/<project_id>/<int:file_id>')
def download(project_id, file_id):
    pf = ProjectFile.query.filter_by(id=file_id, project_id=project_id).first()
    if not pf:
        flash("Nie znaleziono pliku.")
        return redirect(url_for('project_detail', project_id=project_id))
    directory = os.path.abspath(app.config['UPLOAD_FOLDER'])
    return send_from_directory(directory, os.path.basename(pf.file_path), as_attachment=True)

########################################
# Uruchomienie
########################################

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
