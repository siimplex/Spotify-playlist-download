import random

from hashlib import sha256
from base64 import b64encode


def generate_random_string(len):
	possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
	return "".join(random.choices(possible, k=len))


def generate_code_challenge(code_verifier):
	digest = sha256(code_verifier.encode()).digest()
	return b64encode(digest).decode().replace('+', '-').replace('/', '_').replace('=', '').encode()


# from google https://developers.google.com/youtube/v3/guides/auth/server-side-web-apps#python_2
def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}


def transform_json_playlist_to_list(playlist_json):
	track_list = []

	for track in playlist_json:
		track_name = track['track']['name']
		artists_names = []
		
		for artist in track['track']['artists']:
			artists_names.append(artist['name'])

		track_list.append(track_name + " " + ' '.join(artists_names))

	return track_list

