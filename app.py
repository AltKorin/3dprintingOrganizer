import os
import io
import uuid
import trimesh
import requests # New import for PayU integration
from google.cloud import storage
from datetime import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth

hashed_password = generate_password_hash("testpassword123$")
print(len(hashed_password))
passwordlenght = len(hashed_password)

# Ustawienie connection string do Cloud SQL (upewnij się, że prefiks /cloudsql/ jest obecny)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Sudomie1952$'

# Google OAuth configuration
app.config['GOOGLE_CLIENT_ID'] = '666989927124-dr1um1fe20bm7rs46nodrgfks3968v7u.apps.googleusercontent.com'
app.config['GOOGLE_CLIENT_SECRET'] = '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'
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"

# PayU configuration
app.config['PAYU_POS_ID'] = '4356703'
app.config['PAYU_SECOND_KEY'] = '7028999a81ae48f13197481f99f6a52e'
app.config['PAYU_CLIENT_ID'] = '4356703'
app.config['PAYU_CLIENT_SECRET'] = '564b7ef99607426ce84258d7b48fb5c4'
app.config['PAYU_API_URL'] = 'https://secure.snd.payu.com'

# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={
        'scope': 'openid email profile',
    }
)
# Check environment – Google Cloud vs. local MySQL
gae_env = os.getenv('GAE_ENV', '')
print(f"GAE_ENV: {gae_env}")


# Sprawdzenie środowiska – Google Cloud vs. lokalny MySQL
if os.getenv('GAE_ENV', '').startswith('standard'):
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        "mysql+pymysql://produkcjaDB:Sudomie1952Stolem@/db3dprinter"
        "?unix_socket=/cloudsql/dprintingorganiser:europe-central2:db3dprinter"
    )
    app.config['CLOUD_STORAGE_BUCKET'] = "upload_3dprinting_organiser"
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        "mysql+pymysql://produkcjaDB:Sudomie1952Stolem@localhost:3306/db3dprinter"
    )

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicjalizacja bazy danych i login_manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

print("Using database URI:", app.config['SQLALCHEMY_DATABASE_URI'])


# Ustawienie UPLOAD_FOLDER
# Jeśli aplikacja działa na App Engine, ustawiamy na /tmp/uploads, bo poza /tmp system plików jest tylko do odczytu.
if os.getenv('GAE_ENV', '').startswith('standard'):
    UPLOAD_FOLDER = os.path.join('/tmp', 'uploads')
else:
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')

CLOUD_STORAGE_BUCKET = "upload_3dprinting_organiser"
app.config['CLOUD_STORAGE_BUCKET'] = "upload_3dprinting_organiser"
print("Using Cloud Storage bucket:", app.config['CLOUD_STORAGE_BUCKET'])

def test_gcs_connection():
    try:
        client = storage.Client()
        buckets = list(client.list_buckets())
        print("Buckets in your project:")
        for bucket in buckets:
            print(bucket.name)
        print("Connection to Google Cloud Storage is successful.")
    except Exception as e:
        print(f"Failed to connect to Google Cloud Storage: {e}")


test_gcs_connection()

# Inicjalizacja Flask-Migrate
migrate = Migrate(app, db)

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
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='client')  # domyślnie 'client'
    my_price_per_ml = db.Column(db.Float, nullable=True)  # opcjonalna wartość ceny dla biznesu
    first_name = db.Column(db.String(80), nullable=False)  # New field for first name
    last_name = db.Column(db.String(80), nullable=False)  # New field for last name
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
    name = db.Column(db.String(256), nullable=False)
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
    client_complete = db.Column(db.Boolean, default=False)
    business_complete = db.Column(db.Boolean, default=False)
    client_accepted_estimate = db.Column(db.Boolean, default=False)
    paid = db.Column(db.Boolean, default=False)  # New field for payment status

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
# Funkcja pomocnicza sprawdzająca rozszerzenie pliku
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'stl', 'obj'}

CLOUD_STORAGE_BUCKET = "upload_3dprinting_organiser"

def upload_file_to_gcs(file_obj, filename):
    try:
        client = storage.Client()
        bucket = client.bucket(app.config['CLOUD_STORAGE_BUCKET'])
        blob = bucket.blob(filename)
        
        # Upewnij się, że wskaźnik pliku jest ustawiony na początek
        file_obj.seek(0)
        
        # Rozpocznij przesyłanie resumable
        resumable_url = blob.create_resumable_upload_session(content_type=file_obj.content_type)
        print(f"Resumable upload session URL: {resumable_url}")
        
        # Przesyłanie pliku w częściach
        chunk_size = 5 * 1024 * 1024  # 5 MB
        headers = {'Content-Type': file_obj.content_type}
        offset = 0

        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                break

            response = requests.put(
                resumable_url,
                data=chunk,
                headers=headers,
                params={'upload_id': resumable_url.split('/')[-1], 'offset': offset}
            )

            if response.status_code not in [200, 201, 308]:
                raise Exception(f"Failed to upload chunk: {response.text}")

            offset += len(chunk)
        
        print(f"Upload response status code: {response.status_code}")
        print(f"Upload response text: {response.text}")
        
        if response.status_code in [200, 201]:
            return blob.public_url
        else:
            raise Exception(f"Failed to upload file {filename}: {response.text}")
    except Exception as e:
        print(f"Exception during file upload: {e}")
        raise

########################################
# ROUTY
########################################

@app.route('/')
def index():
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
    global_price = get_global_price()  # Ensure this function is defined
    return render_template("business_dashboard.html", projects=projects, global_price=global_price)

@app.route('/client/dashboard')
@login_required
def client_dashboard():
    if current_user.role != 'client':
        flash("Brak dostępu do panelu klienta.")
        return redirect(url_for('index'))
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template("client_dashboard.html", projects=projects)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        role = request.form.get("role")
        
        if role not in ['client', 'business']:
            flash("Nieprawidłowa rola użytkownika.")
            return redirect(url_for('register'))
        
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Użytkownik o takiej nazwie lub emailu już istnieje.")
            return redirect(url_for('register'))
        
        user = User(username=username, email=email, first_name=first_name, last_name=last_name, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash("Rejestracja zakończona powodzeniem. Możesz się teraz zalogować.")
        return redirect(url_for('login'))
    
    return render_template("register.html")

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

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token)
    if user_info:
        email = user_info['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(username=user_info['name'], email=email, role='client')
            db.session.add(user)
            db.session.commit()
        login_user(user)
        flash("Zalogowano pomyślnie.")
        return redirect(url_for('index'))
    flash("Nie udało się zalogować.")
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Wylogowano.")
    return redirect(url_for('index'))

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
        upload_option = request.form.get("upload_option")
        
        if upload_option == 'file':
            if 'files' not in request.files:
                flash("Brak plików w żądaniu.")
                return redirect(request.url)
            files = request.files.getlist('files')
            if not files or files[0].filename == '':
                flash("Nie wybrano żadnych plików.")
                return redirect(request.url)
            
            project_files = []
            total_volume_mm3 = 0
            
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4()}_{filename}"
                    
                    # Wczytaj zawartość pliku do pamięci
                    file_bytes = file.read()
                    
                    # Osobny BytesIO dla obliczeń (trimesh)
                    file_for_trimesh = io.BytesIO(file_bytes)
                    try:
                        file_type = filename.split('.')[-1]
                        mesh = trimesh.load(file_for_trimesh, file_type=file_type, force='mesh')
                        total_volume_mm3 += mesh.volume
                    except Exception as e:
                        flash(f"Błąd przy obliczaniu objętości dla pliku {filename}: {e}")
                        return redirect(request.url)
                    
                    # Osobny BytesIO dla uploadu do GCS
                    file_for_upload = io.BytesIO(file_bytes)
                    file_for_upload.content_type = file.content_type
                    
                    # Używamy funkcji upload_file_to_gcs, która korzysta z resumable uploads dla dużych plików
                    try:
                        file_url = upload_file_to_gcs(file_for_upload, unique_filename)
                        project_files.append((filename, file_url))
                    except Exception as e:
                        flash(f"Nie udało się przesłać pliku {filename}: {e}")
                        return redirect(request.url)
                else:
                    flash("Niedozwolony typ pliku. Dozwolone są tylko .stl i .obj")
                    return redirect(request.url)
            
            volume_ml = total_volume_mm3 / 1000.0
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
        
        elif upload_option == 'link':
            file_link = request.form.get("file_link")
            if not file_link:
                flash("Podaj link do pliku.")
                return redirect(request.url)
            
            project = Project(
                user_id=current_user.id,
                name=project_name,
                main_file_name=file_link,
                main_file_path=file_link,
                volume_ml=0,  # Brak obliczeń dla linku
                estimated_cost=0,
                state="projekt",
                quantity=quantity,
                order_comment=order_comment
            )
            db.session.add(project)
            db.session.commit()
            
            flash(f"Projekt '{project_name}' utworzony z linkiem do pliku.")
            if current_user.role == 'client':
                return redirect(url_for('client_dashboard'))
            elif current_user.role == 'business':
                return redirect(url_for('business_dashboard'))
            else:
                return redirect(url_for('admin_dashboard'))
    
    return render_template("upload.html")

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
                    log = ProjectStateLog(project_id=project.id, old_state=old_state, new_state=new_state, changed_by=current_user.username)
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
                    log = ProjectStateLog(project_id=project.id, old_state=old_state, new_state=new_state, changed_by=current_user.username)
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
                    log = ProjectStateLog(project_id=project.id, old_state=old_state, new_state=new_state, changed_by=current_user.username)
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
                    log = ProjectStateLog(project_id=project.id, old_state=old_state, new_state=new_state, changed_by=current_user.username)
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

@app.route('/download/<project_id>/<int:file_id>')
def download(project_id, file_id):
    pf = ProjectFile.query.filter_by(id=file_id, project_id=project_id).first()
    if not pf:
        flash("Nie znaleziono pliku.")
        return redirect(url_for('project_detail', project_id=project_id))
    directory = os.path.abspath(app.config['UPLOAD_FOLDER'])
    return send_from_directory(directory, os.path.basename(pf.file_path), as_attachment=True)

@app.route('/project/client_complete/<project_id>', methods=['POST'])
@login_required
def client_complete_project(project_id):
    project = db.session.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        flash("Nie masz dostępu do tego projektu.")
        return redirect(url_for('index'))
    
    project.client_complete = True
    if project.client_complete and project.business_complete:
        project.state = "complete"
    db.session.commit()
    flash("Projekt został oznaczony jako zakończony przez klienta.")
    return redirect(url_for('client_dashboard'))

@app.route('/project/business_complete/<project_id>', methods=['POST'])
@login_required
def business_complete_project(project_id):
    project = db.session.get(Project, project_id)
    if not project or current_user.role != 'business':
        flash("Nie masz dostępu do tego projektu.")
        return redirect(url_for('index'))
    
    project.business_complete = True
    if project.client_complete and project.business_complete:
        project.state = "complete"
    db.session.commit()
    flash("Projekt został oznaczony jako zakończony przez biznes.")
    return redirect(url_for('business_dashboard'))

@app.route('/project/delete/<project_id>', methods=['POST'])
@login_required
def delete_project(project_id):
    project = db.session.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        flash("Nie masz dostępu do tego projektu.")
        return redirect(url_for('index'))
    
    # Delete associated files
    ProjectFile.query.filter_by(project_id=project_id).delete()
    # Delete associated state logs
    ProjectStateLog.query.filter_by(project_id=project_id).delete()
    # Delete the project
    db.session.delete(project)
    db.session.commit()
    flash("Projekt został usunięty.")
    return redirect(url_for('client_dashboard'))

@app.route('/project/admin_complete/<project_id>', methods=['POST'])
@login_required
def admin_complete_project(project_id):
    project = db.session.get(Project, project_id)
    if not project or current_user.role != 'admin':
        flash("Nie masz dostępu do tego projektu.")
        return redirect(url_for('index'))
    
    project.state = "complete"
    db.session.commit()
    flash("Projekt został oznaczony jako zakończony przez administratora.")
    return redirect(url_for('admin_dashboard'))

@app.route('/project/admin_delete/<project_id>', methods=['POST'])
@login_required
def admin_delete_project(project_id):
    project = db.session.get(Project, project_id)
    if not project or current_user.role != 'admin':
        flash("Nie masz dostępu do tego projektu.")
        return redirect(url_for('index'))
    
    # Delete associated files
    ProjectFile.query.filter_by(project_id=project_id).delete()
    # Delete associated state logs
    ProjectStateLog.query.filter_by(project_id=project_id).delete()
    # Delete the project
    db.session.delete(project)
    db.session.commit()
    flash("Projekt został usunięty przez administratora.")
    return redirect(url_for('admin_dashboard'))

@app.route('/project/client_accept_estimate/<project_id>', methods=['POST'])
@login_required
def client_accept_estimate(project_id):
    project = db.session.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        flash("Nie masz dostępu do tego projektu.")
        return redirect(url_for('index'))
    
    project.client_accepted_estimate = True
    db.session.commit()
    flash("Wycena została zaakceptowana.")
    return redirect(url_for('client_dashboard'))

# Routy do płacenia przez PayU
@app.route('/pay/<string:project_id>', methods=['POST'])
@login_required
def pay(project_id):
    project = Project.query.get_or_404(project_id)
    
    if not project.client_accepted_estimate:
        flash('Musisz zaakceptować ostateczną wycenę przed dokonaniem płatności.', 'error')
        return redirect(url_for('client_dashboard'))
    
    if project.final_cost is None:
        flash('Ostateczna cena nie została ustawiona.', 'error')
        return redirect(url_for('client_dashboard'))
    
    access_token = get_payu_access_token()
    if not access_token:
        return redirect(url_for('client_dashboard'))
    
    order_data = {
        "notifyUrl": url_for('payment_callback', _external=True),
        "customerIp": request.remote_addr,
        "merchantPosId": app.config['PAYU_POS_ID'],
        "description": f"3D Printing Service - {project.name}",
        "currencyCode": "PLN",
        "totalAmount": str(int(project.final_cost * 100)),  # Amount in grosz (1 PLN = 100 grosz)
        "buyer": {
            "email": current_user.email,
            "firstName": current_user.first_name,
            "lastName": current_user.last_name,
            "language": "pl"
        },
        "products": [
            {
                "name": f"3D Printing Service - {project.name}",
                "unitPrice": str(int(project.final_cost * 100)),
                "quantity": "1"
            }
        ]
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    response = requests.post(f"{app.config['PAYU_API_URL']}/api/v2_1/orders", json=order_data, headers=headers)
    
    if response.status_code == 302:
        return redirect(response.headers['Location'])
    else:
        # Log the response for debugging
        print("PayU API response status code:", response.status_code)
        print("PayU API response text:", response.text)
        flash('Payment initiation failed.', 'error')
        return redirect(url_for('client_dashboard'))

def get_payu_access_token():
    data = {
        "grant_type": "client_credentials",
        "client_id": app.config['PAYU_CLIENT_ID'],
        "client_secret": app.config['PAYU_CLIENT_SECRET']
    }
    response = requests.post(f"{app.config['PAYU_API_URL']}/pl/standard/user/oauth/authorize", data=data)
    
    # Log the response for debugging
    print("PayU Token API response status code:", response.status_code)
    print("PayU Token API response text:", response.text)
    
    if response.status_code == 200:
        return response.json().get("access_token")
    else:
        flash('Failed to obtain access token from PayU.', 'error')
        return None

@app.route('/payment_callback', methods=['POST'])
def payment_callback():
    data = request.json
    order_id = data.get('order', {}).get('orderId')
    status = data.get('order', {}).get('status')
    
    if status == 'COMPLETED':
        project = Project.query.filter_by(order_id=order_id).first()
        if project:
            project.paid = True
            db.session.commit()
            flash("Płatność zakończona sukcesem.", "success")
        else:
            flash("Nie znaleziono projektu dla tego zamówienia.", "error")
    else:
        flash("Płatność nie powiodła się.", "error")
    
    return jsonify({'status': 'ok'})

########################################
# Uruchomienie
########################################

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
