import requests
from time import time

from urllib.parse import urlencode
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
import googleapiclient.discovery
import google_auth_oauthlib.flow

from pytube import Playlist
from helpers import generate_random_string, generate_code_challenge, transform_json_playlist_to_list, credentials_to_dict
from main import app


def make_spotify_get_request(session, url, params={}):
	headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Accept': 'application/json',
		'Authorization': "Bearer " + session['spotify_credentials']['access_token'],
	}
	
	response = requests.get(url, headers=headers, params=params)

	if response.status_code == 200:
		return response.json()
	elif response.status_code == 401 and update_spotify_token_status(session):
		return make_spotify_get_request(session, url, params)
	else:
		app.logger.error("make_spotify_get_request: " + str(response.status_code))
		raise HttpError


def make_spotify_post_request(session, url, data={}):
	headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': "Basic " + app.config['AUTHORIZATION'],
	}

	response = requests.post(url, headers=headers, data=data)

	if response.status_code == 200 or response.status_code == 204:
		return response.json()
	elif response.status_code == 401 and update_spotify_token_status(session):
		return make_spotify_post_request(session, url, data)
	else:
		app.logger.error('make_spotify_post_request: ' + str(response.status_code))
		return None


def update_spotify_token_status(session):
	if time() > session['spotify_credentials']['access_token_expiration']:
		tokens = refresh_spotify_token(session)

		if tokens: 
			session['spotify_credentials']['access_token'] = tokens[0]
			session['spotify_credentials']['expires_in'] = tokens[1]
			session['spotify_credentials']['access_token_expiration'] = time() + float(tokens[1])
		else:
			app.logger.error('update_spotify_token_status using refresh_spotify_token')
			return 0

	return 1


def get_spotify_token(session, code):
	token_url = 'https://accounts.spotify.com/api/token'

	client_id = app.config['CLIENT_ID']
	redirect_uri = app.config['REDIRECT_URI']
	code_verifier = session['spotify_credentials']['code_verifier']

	body = {
		'grant_type': "authorization_code",
		'code': code,
		'redirect_uri': redirect_uri,
		'client_id': client_id,
		'code_verifier': code_verifier,
	}

	response_json = make_spotify_post_request(session, token_url, body)

	if response_json:
		return response_json['access_token'], response_json['refresh_token'], response_json['expires_in']
	return None


def refresh_spotify_token(session):
	token_url = 'https://accounts.spotify.com/api/token'

	client_id = app.config['CLIENT_ID']
	refresh_token = session['spotify_credentials']['refresh_token']

	body = {
		'grant_type': 'refresh_token',
		'refresh_token': refresh_token,
		'client_id': client_id,
	}

	response_json = make_spotify_post_request(session, token_url, body)

	if response_json:
		return response_json['access_token'], response_json['expires_in']
	return None


def make_youtube_request(session, function, method, args):
	credentials = Credentials(**session['google_credentials'])

	api_service_name = app.config['GOOGLE_API_SERVICE_NAME']
	api_version = app.config['GOOGLE_API_VERSION']

	youtube = googleapiclient.discovery.build(api_service_name, api_version, credentials=credentials)

	function = getattr(youtube, function)()
	method = getattr(function, method)
	
	response = method(**args).execute()

	session['google_credentials'] = credentials_to_dict(credentials=credentials)

	return response


def authorize_spotify(session):
	client_id = app.config['CLIENT_ID']
	redirect_uri = app.config['REDIRECT_URI']
	scope = app.config['SPOTIFY_SCOPES']
	len = app.config['CODE_VERIFIER_LEN']

	state = generate_random_string(16)

	code_verifier = generate_random_string(len)
	code_challenge = generate_code_challenge(code_verifier)

	credentials = {}

	session['state'] = state
	credentials['code_verifier'] = code_verifier

	session['spotify_credentials'] = credentials

	authorize_url = 'https://accounts.spotify.com/en/authorize?'
	params = {
		'response_type': 'code',
		'client_id': client_id,
		'scope': scope,
		'redirect_uri': redirect_uri,
		'state': state,
		'code_challenge_method': 'S256',
		'code_challenge': code_challenge
		}

	query_params = urlencode(params)

	url = authorize_url + query_params
	return url


def authorize_google(session):
    flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(app.config
    ['GOOGLE_CLIENT_SECRETS_FILE'], scopes=app.config['GOOGLE_SCOPES'])

    flow._OOB_REDIRECT_URI = 'http://localhost:5000/g_callback' # hack
    flow.redirect_uri = 'http://localhost:5000/g_callback'

    authorization_url, state = flow.authorization_url(
        access_tyte='offline', 
        prompt='consent',
        include_granted_scopes='true')

    session['google_state'] = state

    return authorization_url


def parse_spotify_playlist_id(playlist):
	# basic check for valid spotify url
	if playlist.strip().startswith("https://open.spotify.com/playlist/"):
		playlist = playlist.split('/')[-1].split('?')[0]
	if len(playlist.strip()) == 22:
		return playlist
	return None


def get_spotify_playlist_name(session, playlist_id):
	playlist_endpoint = 'https://api.spotify.com/v1/playlists/'
	response_json = make_spotify_get_request(session, playlist_endpoint + playlist_id, { "fields": "name" })
	return response_json['name']


def get_spotify_playlist_tracks(session, playlist_id):
	playlist_endpoint = 'https://api.spotify.com/v1/playlists/'
	limit_per_request = app.config['SPOTIFY_TRACKS_PER_REQUEST_LIMIT'] 

	response_json = make_spotify_get_request(session, playlist_endpoint + playlist_id + "/tracks", { "fields": "total" })

	total_tracks = int(response_json['total'])

	params = {
		"fields": "items(track(name), track(artists(name))), total, limit",
		"offset": 0,
		"limit": limit_per_request,
	}

	tracks_with_artists = []

	while total_tracks > 0:
		response_json = make_spotify_get_request(session, playlist_endpoint + playlist_id + "/tracks", params)
		app.logger.info("Request: " + str(response_json['total']) + " " + str(response_json['limit']))

		partial_track_list = transform_json_playlist_to_list(response_json['items'])
		tracks_with_artists.extend(partial_track_list)

		total_tracks -= limit_per_request
		params['offset'] += limit_per_request
		
	app.logger.info(f"get_spotify_playlist_tracks: {tracks_with_artists[::-1]}")
	return tracks_with_artists[::-1]


def create_youtube_playlist(session, playlist_name):
	args = {'part': 'snippet, status', 
		'body': {
			"snippet": {
				"title": playlist_name,
				"description": "Playlist create via API using " + app.config['APP_NAME'],
				"tags": [
					"sample playlist",
					"API call"
				],
				"defaultLanguage": "en"
			},
			"status": {
				"privacyStatus": "unlisted"
			}
		}
	}
	try:
		data = make_youtube_request(session, 'playlists', 'insert', args)
	except HttpError as he:
		app.logger.error("create_youtube_playlist: error while creating youtube playlist " + he._get_reason())
		raise

	app.logger.info("create_youtube_playlist: created youtube playlist")
	return data['id']


def search_youtube_with_list(session, queries):
	video_ids = []
	args = {'part': 'snippet', 'type': 'video', 'fields': 'items(id)', 'maxResults': 1, 'q': ""}

	for query in queries:
		args['q'] = query
		try:
			data = make_youtube_request(session, 'search', 'list', args)
			if len(data['items']) == 1: 
				video_ids.append(data['items'][0]['id']['videoId'])
		except HttpError as he:
			app.logger.error("search_youtube_with_list: error while searching for \"" + query + "\"; " + he._get_reason())
			continue

	return video_ids


def insert_videos_into_youtube_playlist(session, playlist_id, video_ids):
	args = {'part': 'snippet', 
			'body': {
				"snippet": {
					"playlistId": playlist_id,
					"position": 0,
					"resourceId": {
						"kind": "youtube#video",
						"videoId": ""
					},
				}
			}
		}
	
	for vid in video_ids:
		args['body']['snippet']['resourceId']['videoId'] = vid
		try:
			data = make_youtube_request(session, 'playlistItems', 'insert', args)
			app.logger.info(f"insert_videos_into_youtube_playlist: inserted video {vid} in {playlist_id}")
		except HttpError as he:
			if he.resp.status == 403:
				app.logger.error("insert_videos_into_youtube_playlist: " + he._get_reason())
				break
			else:
				app.logger.error("insert_videos_into_youtube_playlist: error while inserting into playlist " + vid + "; " + he._get_reason())
				continue
	
	app.logger.info(f"insert_videos_into_youtube_playlist: finished insertion in {playlist_id}")
	return 0


def create_playlist_and_insert_videos(session, playlist_name, playlist_tracks):
	youtube_playlist_id = create_youtube_playlist(session, playlist_name)
	video_ids = search_youtube_with_list(session, playlist_tracks) 
	insert_result = insert_videos_into_youtube_playlist(session, youtube_playlist_id, video_ids)

	return youtube_playlist_id


def download_playlist(playlist_id):
	playlist_url = f"https://www.youtube.com/playlist?list={playlist_id}"
	p = Playlist(playlist_url)
	app.logger.info(f"##### Downloading playlist at {playlist_url}")

	for video in p.videos:
		app.logger.info(f"# Downloading audio from {video.title}")
		video.streams.filter(only_audio=True).first().download(output_path="./test_download")
