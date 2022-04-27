#Importarndo  flask y algunos paquetes para la session y BD
from flask import Flask, render_template, request, redirect, url_for, session

from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
from werkzeug.security import generate_password_hash, check_password_hash

#Creando un Sistema de inicio de sesión y registro con Python Flask y MySQL

#Declarando nombre de la aplicación e inicializando
app = Flask(__name__)


#Ahora, necesitamos crear MySQL y las variables relacionadas
#con la aplicación y configurar los detalles de conexión de MySQL.

# Cambiar esto a su clave secreta
app.secret_key = 'your secret key'

# Ingrese los detalles de conexión de su base de datos
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'pythonlogin'

# Inicializar MySQL
mysql = MySQL(app)
#Asegúrese de configurar las variables de MySQL para reflejar sus detalles de MySQL


# http://localhost:5000/pythonlogin/ - pagina, inicio de sesión, que utilizará solicitudes GET y POST
@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    # Mensaje de salida si algo sale mal...
    msg = ''
    # Compruebe si existen solicitudes POST de "nombre de usuario" y "contraseña" (formulario enviado por el usuario)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Crear variables para facilitar el acceso
        username = request.form['username']
        password = request.form['password']
        
        # Comprobar si existe una cuenta usando MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM accounts WHERE username = %s", [username])
        # Obtener un registro y devolver el resultado
        account = cursor.fetchone()
        
        # Si la cuenta existe en la tabla de cuentas en la base de datos, se declaran las variables de sesión
        if account:
            if check_password_hash(account['password'],password):
                # Crear datos de sesión, podemos acceder a estos datos en otras rutas
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
            # Redirigir a la página de inicio
            return redirect(url_for('home'))
        else:
            # La cuenta no existe o el nombre de usuario/contraseña es incorrecto
            msg = 'Incorrect username/password!'
            
    # Mostrar el formulario de inicio de sesión con el mensaje (si corresponde)
    return render_template('index.html', msg=msg)



# http://localhost:5000/python/logout - Esta será la página de cierre de sesión
# este código eliminará cada variable de sesión asociada con el usuario.
# Sin estas variables de sesión, el usuario no puede iniciar sesión. Posteriormente, 
# el usuario es redirigido a la página de inicio de sesión.
@app.route('/pythonlogin/logout')
def logout():
    # Eliminar datos de sesión, esto cerrará la sesión del usuario
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirigir a la página de inicio de sesión
   return redirect(url_for('login'))



# http://localhost:5000/pythinlogin/register - Esta será la página de registro, 
# necesitamos usar solicitudes GET y POST
@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    # Mensaje de salida si algo sale mal...
    msg = ''
    # Compruebe si existen solicitudes POST de "nombre de usuario", "contraseña" y "correo electrónico" (formulario enviado por el usuario)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Crear variables para facilitar el acceso
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Comprobar si existe una cuenta usando MySQL, con respecto al email
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        # Si la cuenta existe, muestra los controles de error y validación.
        if account:
            msg = 'la cuenta ya existe!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Dirección de correo electrónico no válida!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'El nombre de usuario debe contener solo caracteres y números!'
        elif not username or not password or not email:
            msg = 'por favor rellena el formulario!'
        else:
            # La cuenta no existe y los datos del formulario son válidos,
            # ahora inserte una nueva cuenta en la tabla de cuentas
            nueva_password = generate_password_hash(password, method='sha256')
            cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, nueva_password, email,))
            mysql.connection.commit()
            msg = 'Se ha registrado exitosamente!'
            
    elif request.method == 'POST':
        # El formulario está vacío... (sin datos POST)
        msg = 'por favor rellena el formulario!'
    # Mostrar formulario de registro con mensaje (si lo hay)
    return render_template('register.html', msg=msg)



# http://localhost:5000/pythinlogin/home - esta será la página de inicio, 
# solo accesible para usuarios registrados
# Si el usuario ha iniciado sesión, tendrá acceso a la página de inicio.
# De lo contrario, serán redirigidos a la página de inicio de sesión.
@app.route('/pythonlogin/home')
def home():
    # Compruebe si el usuario está conectado
    if 'loggedin' in session:
        # El usuario ha iniciado sesión mostrarles la página de inicio
        return render_template('home.html', username=session['username'])
    # El usuario no ha iniciado sesión redirigido a la página de inicio de sesión
    return redirect(url_for('login'))




# http://localhost:5000/pythinlogin/profile - esta será la página de perfil, solo accesible para usuarios registrados
@app.route('/pythonlogin/profile')
def profile():
    # Compruebe si el usuario está conectado
    if 'loggedin' in session:
        # Necesitamos toda la información de la cuenta del usuario para poder mostrarla en la página de perfil.
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Mostrar la página de perfil con información de la cuenta
        return render_template('profile.html', account=account)
    # El usuario no ha iniciado sesión redirigido a la página de inicio de sesión
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True, port=5000)