# ios_unencrypted_backup_extract_files
Extract files from unencrypted and encrypted IOS backup

**Full credits to https://github.com/jsharkey13/iphone_backup_decrypt**

the script is modified to also work with unencrypted backups. Works straight from the command line which is slightly different from the above source.
Feel free to fork and modify. Use carefully, as this may have errors - i havent stress tested this.

**Syntax:
**$ python3 ios_extract_files.py
usage: ios_extract_files.py [-h] [-p PASSWORD] [--relpath RELPATH] [--domain DOMAIN] [--fileid FILEID] [--save-manifest SAVE_MANIFEST] [--preserve-folders]
                            [--domain-folders] [--incremental] [--test]
                            backup_dir output_dir
ios_extract_files.py: error: the following arguments are required: backup_dir, output_dir

**relpath:**
Should work with all of the below as well as domain wildcards (not listed below, refer the source above)
 """Relative paths for commonly accessed files."""

    # Standard iOS file locations:
    ADDRESS_BOOK = "Library/AddressBook/AddressBook.sqlitedb"
    TEXT_MESSAGES = "Library/SMS/sms.db"
    CALL_HISTORY = "Library/CallHistoryDB/CallHistory.storedata"
    NOTES = "Library/Notes/notes.sqlite"
    CALENDARS = "Library/Calendar/Calendar.sqlitedb"
    HEALTH = "Health/healthdb.sqlite"
    HEALTH_SECURE = "Health/healthdb_secure.sqlite"
    SAFARI_HISTORY = "Library/Safari/History.db"
    SAFARI_BOOKMARKS = "Library/Safari/Bookmarks.db"

    # Very common external files:
    WHATSAPP_MESSAGES = "ChatStorage.sqlite"
    WHATSAPP_CONTACTS = "ContactsV2.sqlite"

    """Relative path wildcards for commonly accessed groups of files."""

    # A wildcard, use at own risk:
    ALL_FILES = "%"

    # Standard iOS file locations:
    CAMERA_ROLL = "Media/DCIM/%APPLE/IMG%.%"
    ICLOUD_PHOTOS = "Media/PhotoData/CPLAssets/group%/%.%"
    SMS_ATTACHMENTS = "Library/SMS/Attachments/%.%"
    VOICEMAILS = "Library/Voicemail/%.amr"
    VOICE_RECORDINGS = "Library/Recordings/%"
    ICLOUD_LOCAL_FILES = "Library/Mobile Documents/com~apple~CloudDocs/%"

    # WhatsApp makes .thumb files for every media item, so maybe specifically extract JPG or MP4:
    WHATSAPP_ATTACHED_IMAGES = "Message/Media/%.jpg"
    WHATSAPP_ATTACHED_VIDEOS = "Message/Media/%.mp4"
    # But allow full export if desired:
    WHATSAPP_ATTACHMENTS = "Message/Media/%.%"


**Examples: **
python3 ios_extract_files.py <backup_location> <output_location> --relpath Library/SMS/sms.db  #TEXT_MESSAGES
python3 ios_extract_files.py <backup_location> <output_location> --relpath ChatStorage.sqlite  #WHATSAPP_MESSAGES
python3 ios_extract_files.py <backup_location> <output_location> --relpath "Library/SMS/Attachments/%.%"  #SMS_ATTACHMENTS


