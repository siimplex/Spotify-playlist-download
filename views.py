from time import time

from flask import redirect, make_response, render_template, session, request, url_for
import google_auth_oauthlib.flow
from googleapiclient.errors import HttpError

from options import Options
from functions import get_spotify_token, authorize_spotify, authorize_google, parse_spotify_playlist_id, get_spotify_playlist_tracks, get_spotify_playlist_name, create_playlist_and_insert_videos, download_playlist
from main import app

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    return render_template('index.html', options=Options.get_keys())


@app.route("/convert", methods=['POST'])
def convert_spotify_playlist_to_youtube_playlist():
    if 'spotify_credentials' not in session:
        return render_template('index.html', data="Connect your Spotify account", options=Options.get_keys() )
        
    if 'google_credentials' not in session:
        return render_template('index.html', data="Connect your Youtube account", options=Options.get_keys())
    
    if not request.form['playlist_id']:
        return redirect(url_for('index'))

    spotify_playlist_id = parse_spotify_playlist_id(request.form['playlist_id'])
    if not spotify_playlist_id:
        return render_template('index.html', data="Invalid spotify playlist ID", options=Options.get_keys())

    flag = Options.get_key_from_str_value(request.form['option'].split('.')[-1])

    try:
        playlist_name = get_spotify_playlist_name(session, spotify_playlist_id)
        playlist_tracks = get_spotify_playlist_tracks(session, spotify_playlist_id)
    except HttpError:
        return render_template('index.html', data="Failed to retrieve information from spotify API", options=Options.get_keys())

    
    if flag == Options.ONLY_CREATE_PLAYLIST:
        try:
            create_playlist_and_insert_videos(session, playlist_name, playlist_tracks)
        except HttpError:
            return render_template('index.html', data="Failed creating a youtube playlist", options=Options.get_keys())
        result_str = "Sucessfully created a youtube playlist with the songs!"
    elif flag == Options.CREATE_PLAYLIST_AND_DOWNLOAD:
        print("HERE")
        try:
            playlist_id = create_playlist_and_insert_videos(session, playlist_name, playlist_tracks)
        except HttpError:
            return render_template('index.html', data="Failed creating a youtube playlist", options=Options.get_keys())
        
        download_playlist(playlist_id)
        result_str = "Sucessfully created a youtube playlist and downloaded the songs!"
    
    return redirect(url_for('index', data=result_str))


@app.route('/login_spotify')
def login_spotify():
    if 'spotify_credentials' in session:
        return redirect(url_for('index'))
    authorize_url = authorize_spotify(session)
    return redirect(authorize_url)


@app.route('/login_youtube')
def login_youtube():
    if 'google_credentials' in session:
        return redirect(url_for('index'))
    authorize_url = authorize_google(session)
    return redirect(authorize_url)


@app.route('/callback')
def callback():
    if request.args.get('state') != session['state']:
        return render_template('index.html', error="State Missing")
    if request.args.get('error'):
        return render_template('index.html', error="Error")
    else:
        code = request.args.get('code')
        session.pop('state')

        tokens = get_spotify_token(session, code)
        if tokens:
            session['spotify_credentials']['access_token'] = tokens[0]
            session['spotify_credentials']['refresh_token'] = tokens[1]
            session['spotify_credentials']['expires_in'] = tokens[2]
            session['spotify_credentials']['access_token_expiration'] = time() + int(tokens[2])

            return redirect(url_for('index')) 
        else:
            return render_template('index.html', error="Failed to get access token", options=Options.get_keys())


@app.route('/g_callback')
def g_callback():
    state = session['google_state']
    flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(app.config
        ['GOOGLE_CLIENT_SECRETS_FILE'], app.config['GOOGLE_SCOPES'], state=state)
    flow.redirect_uri = url_for('g_callback', _external=True)

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    session['google_credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes}

    session.pop('google_state')

    return redirect(url_for('index')) 


# temp
@app.route('/show_session')
def show_session():
    return render_template('index.html', data=session, options=Options.get_keys())

@app.route('/revoke')
def revoke_session():
    session.clear()
    # gc = 'google_credentials'
    # sc = 'spotify_credentials'
    # if gc in session:
    #     del session[gc]
    # if sc in session:
    #     del session[sc]
    return redirect(url_for('index'))