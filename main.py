from flask import Flask
import os

from config import Config

app = Flask(__name__)
app.config.from_object(Config)

if __name__ == "__main__":
    app.run(debug=True)

import views

# When running locally, disable OAuthlib's HTTPs verification.
# ACTION ITEM for developers:
#     When running in production *do not* leave this option enabled.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'