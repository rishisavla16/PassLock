# secure_password_manager/vault.py

from auth import db, User

def get_vault(user_id):
    """
    Retrieves the encrypted vault and PBKDF2 salt for a user.
    This data is opaque to the server and only useful to the client.
    """
    user = User.query.get(user_id)
    if user:
        return user.encrypted_vault, user.pbkdf2_salt
    return None, None

def update_vault(user_id, encrypted_vault_blob):
    """
    Updates the user's encrypted vault blob in the database.
    The server stores this data without understanding its contents.
    """
    user = User.query.get(user_id)
    if user:
        user.encrypted_vault = encrypted_vault_blob
        db.session.commit()
