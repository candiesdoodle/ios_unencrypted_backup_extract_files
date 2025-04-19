# ios_unencrypted_backup_extract_files
Extract files from unencrypted and encrypted IOS backup

## Full credits to https://github.com/jsharkey13/iphone_backup_decrypt

the script is modified to also work with unencrypted backups. 
Works straight from the command line which is slightly different from the above source.
Feel free to fork and modify. **Use carefully, as this may have errors - i havent stress tested this.**

**Syntax:**
```
$ python3 ios_extract_files.py

usage: ios_extract_files.py [-h] [-p PASSWORD] [--relpath RELPATH] [--domain DOMAIN] [--fileid FILEID] [--save-manifest SAVE_MANIFEST] [--preserve-folders]
                            [--domain-folders] [--incremental] [--test]
                            backup_dir output_dir
                            
ios_extract_files.py: error: the following arguments are required: backup_dir, output_dir
```
Note: As you can see, the command line syntax should work with passphrase encrypted backups too. Again, havent tested this part.

**relpath:**

Relative paths for commonly accessed files.

Should work with all of the below as well as domain wildcards (not listed below, refer the source above)

Note: CALL_HISTORY will be missing in unencrypted backups.

```
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

    Relative path wildcards for commonly accessed groups of files.

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
```

**Examples - TESTED:**
```
python3 ios_extract_files.py <backup_location> <output_location> --relpath Library/SMS/sms.db  #TEXT_MESSAGES
python3 ios_extract_files.py <backup_location> <output_location> --relpath ChatStorage.sqlite  #WHATSAPP_MESSAGES
python3 ios_extract_files.py <backup_location> <output_location> --relpath "Library/SMS/Attachments/%.%"  #SMS_ATTACHMENTS
```

**More examples - NOT TESTED**

Replace `/path/to/your/backup_folder` with the actual path to your iOS backup directory and `/path/to/output` with your desired output directory. Use quotes around paths if they contain spaces.

**1. Test Access (Encrypted Backup - Prompts for Password)**

Checks if the encrypted backup is accessible and prompts for the password. Does not extract files.

```bash
python iphone_backup_extractor.py "/path/to/your/backup_folder" --test
```

**2. Test Access (Encrypted Backup - Provides Password)**

Checks if the encrypted backup is accessible using the provided password. Does not extract files.

```bash
python iphone_backup_extractor.py "/path/to/your/backup_folder" -p "YourBackupPassword" --test
```

**3. Extract SMS Database (Unencrypted)**

Extracts the main SMS database file (`sms.db`) from an unencrypted backup.

```bash
python iphone_backup_extractor.py "/path/to/backup" "/path/to/output" --relpath Library/SMS/sms.db --domain HomeDomain
```

**4. Extract All Camera Roll Files (Encrypted - Prompts for Password)**

Extracts all files from the Camera Roll (`Media/DCIM/`), preserving the original folder structure within the output directory. Prompts for the password.

```bash
python iphone_backup_extractor.py "/path/to/backup" "/path/to/output/CameraRoll" --relpath 'Media/DCIM/%' --domain CameraRollDomain --preserve-folders
```
*(Note: Use quotes around patterns with `%` if your shell interprets it specially)*

**5. Extract WhatsApp Chat Database (Encrypted - Provides Password)**

Extracts the main WhatsApp chat database (`ChatStorage.sqlite`).

```bash
python iphone_backup_extractor.py "/path/to/backup" "/path/to/output/WhatsApp" -p "Password123" --relpath ChatStorage.sqlite --domain 'AppDomainGroup-group.net.whatsapp.WhatsApp.shared'
```

**6. Extract All WhatsApp Files (Unencrypted)**

Extracts *all* files associated with the WhatsApp domain, organizing them into a `AppDomainGroup-group.net.whatsapp.WhatsApp.shared` subfolder within the output directory, and preserving the original file paths within that subfolder.

```bash
python iphone_backup_extractor.py "/path/to/backup" "/path/to/output" --domain 'AppDomainGroup-group.net.whatsapp.WhatsApp.shared' --domain-folders --preserve-folders
```

**7. Save Decrypted Manifest Database (Encrypted - Provides Password)**

Saves a *decrypted* copy of the backup's `Manifest.db` file, which contains the index of all files in the backup. No other files are extracted.

```bash
python iphone_backup_extractor.py "/path/to/backup" "." -p "Password123" --save-manifest decrypted_manifest.db
```
*(Note: `.` is used as a placeholder output directory as only the manifest is being saved)*

**8. Extract Specific File by ID (Unencrypted)**

Extracts a single file identified by its SHA1 hash (`fileID`) as stored within the backup structure.

```bash
python iphone_backup_extractor.py "/path/to/backup" "/path/to/output" --fileid ff13ada7e4238799fbd851a9ab4f75cafc78545d
```

**9. Extract SMS Attachments Incrementally (Encrypted - Prompts)**

Extracts all SMS attachments, preserving folder structure. If run previously, only extracts files that are new or have been updated in the backup since the last extraction.

```bash
python iphone_backup_extractor.py "/path/to/backup" "/path/to/output/SMS_Attachments" --relpath 'Library/SMS/Attachments/%.%' --domain HomeDomain --preserve-folders --incremental
```
```
