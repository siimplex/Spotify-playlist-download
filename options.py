from enum import Enum

class Options(Enum):
    ONLY_CREATE_PLAYLIST = "Convert to youtube playlist"
    CREATE_PLAYLIST_AND_DOWNLOAD = "Convert to youtube playlist and download songs"

    @classmethod
    def get_keys(cls):
        return [o for o in Options]
    
    @classmethod
    def get_key_from_str_value(cls, str: str):
        if str.upper() == "ONLY_CREATE_PLAYLIST":
            return Options.ONLY_CREATE_PLAYLIST
        if str.upper() == "CREATE_PLAYLIST_AND_DOWNLOAD":
            return Options.CREATE_PLAYLIST_AND_DOWNLOAD
        return None