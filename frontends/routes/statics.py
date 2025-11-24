# Load static files

from flask import Blueprint, send_from_directory
import os
statics_css = Blueprint('statics', __name__, static_folder='../templates/css')
statics_js = Blueprint('statics_js', __name__, static_folder='../templates/js')

@statics_css.route('/css/<path:filename>')
def serve_css(filename):
    return send_from_directory(os.path.join(statics_css.root_path, 'css'), filename)

@statics_js.route('/js/<path:filename>')
def serve_js(filename):
    return send_from_directory(os.path.join(statics_js.root_path, 'js'), filename)