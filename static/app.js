// secure_password_manager/static/app.js

document.addEventListener('DOMContentLoaded', () => {
    // --- State ---
    let encryptionKey = null;
    let vaultData = [];
    let userSalt = null;
    let inactivityTimer;
    let editingIndex = null;

    // --- DOM Elements ---
    const unlockSection = document.getElementById('unlock-vault-section');
    const vaultSection = document.getElementById('vault-content-section');
    const masterPasswordInput = document.getElementById('master-password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const setupModeEl = document.getElementById('is-setup-mode');
    let isSetupMode = setupModeEl ? setupModeEl.value === 'true' : false;
    const unlockButton = document.getElementById('unlock-button');
    const unlockError = document.getElementById('unlock-error');
    const showHintBtn = document.getElementById('show-hint-btn');
    const settingsLink = document.getElementById('settings-link'); // New element
    const cancelEntryBtn = document.getElementById('cancel-entry-btn');
    const showAddEntryBtn = document.getElementById('show-add-entry-btn');
    const addEntryContainer = document.getElementById('add-entry-form');
    const lockButton = document.getElementById('lock-vault-button');
    const newEntryForm = document.getElementById('new-entry-form');
    const entriesTableBody = document.querySelector('#entries-table tbody');
    const emptyVaultMessage = document.getElementById('empty-vault-message');
    const hintForm = document.getElementById('hint-form');
    const hintWrapper = document.getElementById('hint-wrapper');
    const hintInput = document.getElementById('update-hint-input');
    const changePasswordForm = document.getElementById('change-password-form');
    const oldMasterPasswordInput = document.getElementById('old-master-password');
    const newMasterPasswordInput = document.getElementById('new-master-password');
    const confirmNewPasswordInput = document.getElementById('confirm-new-password');
    const changePasswordStatus = document.getElementById('change-password-status');
    const deleteAccountBtn = document.getElementById('delete-account-btn');
    const confirmationModal = document.getElementById('confirmation-modal');
    const changeLoginPasswordForm = document.getElementById('change-login-password-form');
    const enable2faBtn = document.getElementById('enable-2fa-btn');
    const disable2faBtn = document.getElementById('disable-2fa-btn');
    const verify2faForm = document.getElementById('verify-2fa-form');
    const resend2faBtn = document.getElementById('resend-2fa-btn');
    const modalTitle = document.getElementById('modal-title');
    const modalMessage = document.getElementById('modal-message');
    const modalConfirmBtn = document.getElementById('modal-confirm-btn');
    const modalCancelBtn = document.getElementById('modal-cancel-btn');
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : null;

    // --- Initialization ---
    // Security:  Ensure the vault is hidden on page load.
    // The CSS now handles the initial hiding, this just makes absolutely sure.
    //vaultSection.style.display = 'none';  //No longer needed

    if (unlockSection) {
        unlockSection.style.display = 'block';
        masterPasswordInput.value = '';
    }

    // --- Core Functions ---

    /**
     * A wrapper for the fetch API that handles 401 Unauthorized responses
     * by redirecting the user to the login page.
     * @param {string} url The URL to fetch.
     * @param {object} options The options to pass to fetch.
     * @returns {Promise<Response>} A promise that resolves to the fetch Response object.
     */
    async function authenticatedFetch(url, options) {
        const response = await fetch(url, options);
        if (response.status === 401) {
            alert('Your session has expired. Please log in again.');
            // Use replace to prevent the back button from returning to a broken state.
            window.location.replace('/login');
            throw new Error('Session expired'); // Stop further execution
        }
        return response;
    }

    /**
     * Unlocks the vault by deriving the key and decrypting the data.
     */
    async function unlockVault() {
        const masterPassword = masterPasswordInput.value;
        if (!masterPassword) {
            unlockError.textContent = 'Please enter your master password.';
            return;
        }

        if (isSetupMode) {
            const confirmPassword = confirmPasswordInput.value;
            if (masterPassword !== confirmPassword) {
                unlockError.textContent = 'Passwords do not match.';
                return;
            }
        }

        unlockError.textContent = '';
        unlockButton.disabled = true;
        unlockButton.textContent = isSetupMode ? 'Setting up...' : 'Unlocking...';

        try {
            // 1. Fetch the encrypted vault and salt from the server.
            const response = await authenticatedFetch('/api/vault');
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Could not fetch vault data: ${response.status} ${response.statusText} - ${errorText}`);
            }
            const { vault: encryptedVault, salt: saltHex } = await response.json();

            // 2. Derive the encryption key from the master password and salt.
            userSalt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            encryptionKey = await deriveKey(masterPassword, userSalt);

            if (isSetupMode) {
                // 3a. Setup Mode: Initialize empty vault and SAVE it immediately.
                // This ensures the master password is "locked in" on the server.
                vaultData = [];
                await saveVault();
                
                // Update state and UI for future locks within this session
                isSetupMode = false;
                document.querySelector('#unlock-vault-section h2').textContent = 'Unlock Your Vault';
                document.querySelector('#unlock-vault-section p').innerHTML = 'Enter your <strong>Master Password</strong> to decrypt your vault. This password is never sent to the server.';
                if (confirmPasswordInput) {
                    confirmPasswordInput.closest('.form-group').style.display = 'none';
                    confirmPasswordInput.value = '';
                }

                // Transition to vault view
                unlockSection.style.display = 'none';
                vaultSection.style.display = 'block';
                masterPasswordInput.value = '';
                renderVault();
                if (settingsLink) settingsLink.classList.remove('hidden'); // Show settings link
                resetInactivityTimer();
            } else {
                // 3b. Unlock Mode: Decrypt existing data.
                if (!encryptedVault) throw new Error('Vault data missing on server.');
                
                const decryptedJson = await decrypt(encryptedVault, encryptionKey);
                vaultData = JSON.parse(decryptedJson);

                // Transition to vault view
                unlockSection.style.display = 'none';
                vaultSection.style.display = 'block';
                masterPasswordInput.value = '';
                renderVault();
                if (settingsLink) settingsLink.classList.remove('hidden'); // Show settings link
                resetInactivityTimer();
            }

        } catch (error) {
            console.error('Unlock failed:', error);
            unlockError.textContent = `Failed to unlock vault: ${error.message || 'Incorrect master password.'}`;
            encryptionKey = null; // Clear the key on failure.
        } finally {
            unlockButton.disabled = false;
            unlockButton.textContent = isSetupMode ? 'Set Master Password' : 'Unlock';
        }
    }

    /**
     * Encrypts and saves the current vault data to the server.
     */
    async function saveVault() {
        if (!encryptionKey) {
            alert('Error: Vault is not unlocked.');
            return;
        }
        try {
            const plaintext = JSON.stringify(vaultData);
            const encryptedVault = await encrypt(plaintext, encryptionKey);

            const response = await authenticatedFetch('/api/vault', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken // Include CSRF token for security
                },
                body: JSON.stringify({ vault: encryptedVault })
            });

            if (!response.ok) {
                console.error('Server response for saveVault:', await response.text());
                throw new Error('Failed to save vault to server.');
            }
        } catch (error) {
            console.error('Save failed:', error);
            alert('Error saving vault. Please try again.');
        }
    }

    /**
     * Renders the decrypted vault entries into the HTML table.
     */
    function renderVault() {
        entriesTableBody.innerHTML = '';
        if (vaultData.length > 0) {
            emptyVaultMessage.classList.add('hidden');
            vaultData.forEach((entry, index) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td data-label="Site" title="${escapeHtml(entry.site)}">${escapeHtml(entry.site)}</td>
                    <td data-label="Username" title="${escapeHtml(entry.username)}">${escapeHtml(entry.username)}</td>
                    <td data-label="Password" class="password-cell">
                        <div class="password-wrapper">
                        <button class="icon-copy-btn" data-index="${index}" title="Copy Password">📋</button>
                            <span class="password-text" title="Click to toggle visibility">
                                <span class="password-hidden">••••••••</span>
                                <span class="password-revealed">${escapeHtml(entry.password)}</span>
                            </span>
                        </div>
                    </td>
                    <td data-label="Actions" class="actions">
                        <button class="action-btn" data-action="edit" data-index="${index}">Edit</button>
                        <button class="action-btn delete-btn" data-action="delete" data-index="${index}">Delete</button>
                    </td>
                `;
                entriesTableBody.appendChild(row);
            });
        } else {
            emptyVaultMessage.classList.remove('hidden');
        }
    }

    /**
     * Prepares the form for editing an existing entry.
     */
    function startEditing(index) {
        // Ensure form is visible and button is hidden
        addEntryContainer.classList.remove('hidden');
        showAddEntryBtn.classList.add('hidden');

        const entry = vaultData[index];
        document.getElementById('new-site').value = entry.site;
        document.getElementById('new-username').value = entry.username;
        document.getElementById('new-password').value = entry.password;
        
        editingIndex = index;
        const submitBtn = newEntryForm.querySelector('button[type="submit"]');
        submitBtn.textContent = 'Update Entry';
        
        addEntryContainer.scrollIntoView({ behavior: 'smooth' });
    }

    function cancelEditing() {
        editingIndex = null;
        newEntryForm.reset();
        newEntryForm.querySelector('button[type="submit"]').textContent = 'Add Entry';

        // Hide form and show button
        addEntryContainer.classList.add('hidden');
        showAddEntryBtn.classList.remove('hidden');
    }

    /**
     * Locks the vault, clearing all sensitive data from memory and the UI.
     */
    function lockVault(autoLock = false) {
        // Clear sensitive state
        encryptionKey = null;
        vaultData = [];
        userSalt = null;
        masterPasswordInput.value = '';
        
        // Reset edit state if active
        if (editingIndex !== null) {
            cancelEditing();
        }

        // Reset UI
        vaultSection.style.display = 'none';
        unlockSection.style.display = 'block';
        if (settingsLink) settingsLink.classList.add('hidden'); // Hide settings link
        // Reset Add Entry UI state
        if (addEntryContainer) addEntryContainer.classList.add('hidden');
        if (showAddEntryBtn) showAddEntryBtn.classList.remove('hidden');

        if (autoLock === true) {
            unlockError.textContent = 'Vault has been locked due to inactivity';
        } else {
            unlockError.textContent = 'Vault has been locked';
        }

        // Clear timers
        clearTimeout(inactivityTimer);
    }

    /**
     * Shows a custom confirmation modal.
     * @param {string} message - The message to display.
     * @param {string} title - The title of the modal.
     * @returns {Promise<boolean>} Resolves to true if confirmed, false otherwise.
     */
    function showConfirm(message, title = 'Confirm Action') {
        return new Promise((resolve) => {
            modalMessage.textContent = message;
            modalTitle.textContent = title;
            confirmationModal.classList.remove('hidden');

            const handleConfirm = () => {
                cleanup();
                resolve(true);
            };

            const handleCancel = () => {
                cleanup();
                resolve(false);
            };

            const cleanup = () => {
                modalConfirmBtn.removeEventListener('click', handleConfirm);
                modalCancelBtn.removeEventListener('click', handleCancel);
                confirmationModal.classList.add('hidden');
            };

            modalConfirmBtn.addEventListener('click', handleConfirm);
            modalCancelBtn.addEventListener('click', handleCancel);
        });
    }

    /**
     * Shows a custom alert modal (reusing the confirmation modal structure).
     * @param {string} message - The message to display.
     * @param {string} title - The title of the modal.
     * @returns {Promise<void>} Resolves when the user clicks OK.
     */
    function showAlert(message, title = 'Alert') {
        return new Promise((resolve) => {
            modalMessage.textContent = message;
            modalTitle.textContent = title;
            confirmationModal.classList.remove('hidden');
            
            // Adjust UI for Alert mode (Hide Cancel, Change Confirm to OK)
            modalCancelBtn.classList.add('hidden');
            modalConfirmBtn.textContent = 'OK';
            const originalBg = modalConfirmBtn.style.backgroundColor;
            modalConfirmBtn.style.backgroundColor = 'var(--primary-color)'; // Use primary color instead of danger

            const handleConfirm = () => {
                cleanup();
                resolve();
            };

            const cleanup = () => {
                modalConfirmBtn.removeEventListener('click', handleConfirm);
                confirmationModal.classList.add('hidden');
                // Restore UI for standard confirmations
                modalCancelBtn.classList.remove('hidden');
                modalConfirmBtn.textContent = 'Confirm';
                modalConfirmBtn.style.backgroundColor = originalBg;
            };

            modalConfirmBtn.addEventListener('click', handleConfirm);
        });
    }

    // --- Event Handlers ---

    if (unlockButton) {
        unlockButton.addEventListener('click', unlockVault);
    }
    if (showHintBtn) {
        showHintBtn.addEventListener('click', () => {
            const hintText = document.getElementById('master-password-hint'); // Get hintText here
            // The 'is-visible' class will be defined in CSS to set display: block
            const isVisible = hintText.classList.toggle('is-visible');
            showHintBtn.textContent = isVisible ? 'Hide Hint' : 'Show Hint';
        });
    }
    if (masterPasswordInput) {
        masterPasswordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') unlockVault();
        });
    }
    if (confirmPasswordInput) {
        confirmPasswordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') unlockVault();
        });
    }

    if (lockButton) {
        lockButton.addEventListener('click', () => lockVault(false));
    }

    if (showAddEntryBtn) {
        showAddEntryBtn.addEventListener('click', () => {
            addEntryContainer.classList.remove('hidden');
            showAddEntryBtn.classList.add('hidden');
        });
    }

    if (cancelEntryBtn) {
        cancelEntryBtn.addEventListener('click', cancelEditing);
    }
    if (newEntryForm) {
        newEntryForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const newEntry = {
            site: document.getElementById('new-site').value,
            username: document.getElementById('new-username').value,
            password: document.getElementById('new-password').value
        };
        
        if (editingIndex !== null) {
            vaultData[editingIndex] = newEntry;
            cancelEditing();
        } else {
            vaultData.push(newEntry);
            newEntryForm.reset();
            // Hide form and show button after adding
            addEntryContainer.classList.add('hidden');
            showAddEntryBtn.classList.remove('hidden');
        }
        
        renderVault();
        await saveVault();
    });
    }

    // Hint form logic (now potentially on a different page)
    // This block will only execute if hintForm exists on the current page.
    if (hintForm && csrfToken) { // Ensure csrfToken is available
        const hintSaveStatus = document.getElementById('hint-save-status'); // Get status element here
        const hintText = document.getElementById('master-password-hint'); // Get hintText here
        hintForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const newHint = hintInput.value;
            const button = hintForm.querySelector('button[type="submit"]');

            const confirmed = await showConfirm("Are you sure you want to update your password hint?", "Update Hint");
            if (!confirmed) return;

            button.disabled = true;
            hintSaveStatus.textContent = 'Saving...';
            hintSaveStatus.style.color = 'inherit';

            try {
                const response = await authenticatedFetch('/api/hint', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({ hint: newHint })
                });

                if (!response.ok) throw new Error('Server responded with an error.');

                const result = await response.json();
                if (result.status === 'success') {
                    hintSaveStatus.textContent = 'Saved!';
                    hintSaveStatus.style.color = 'green'; 

                    // Update the hint on the unlock screen if it exists (on vault page)
                    if (hintText && hintWrapper) {
                        hintText.textContent = 'Hint: ' + newHint;
                        hintWrapper.classList.toggle('hidden', !newHint);
                        hintText.classList.remove('is-visible'); // Reset state
                        if (showHintBtn) showHintBtn.textContent = 'Show Hint';
                    }
                } else {
                    throw new Error(result.message || 'Failed to save hint.');
                }
            } catch (error) {
                console.error('Hint save failed:', error);
                hintSaveStatus.textContent = 'Error!';
                hintSaveStatus.style.color = 'red';
            } finally {
                button.disabled = false;
                setTimeout(() => { hintSaveStatus.textContent = ''; }, 3000);
            }
        });
    }

    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const oldPassword = oldMasterPasswordInput.value;
            const newPassword = newMasterPasswordInput.value;
            const confirmPassword = confirmNewPasswordInput.value;
    
            changePasswordStatus.textContent = '';
    
            if (!oldPassword || !newPassword || !confirmPassword) {
                changePasswordStatus.textContent = 'All fields are required.';
                changePasswordStatus.style.color = 'red';
                return;
            }
    
            if (newPassword !== confirmPassword) {
                changePasswordStatus.textContent = 'New passwords do not match.';
                changePasswordStatus.style.color = 'red';
                return;
            }
    
            const button = changePasswordForm.querySelector('button[type="submit"]');
            button.disabled = true;
            changePasswordStatus.textContent = 'Verifying...';
            changePasswordStatus.style.color = 'inherit';
    
            try {
                // This process is self-contained to work on any page.
                // 1. Fetch user's salt and current encrypted vault.
                const vaultApiResponse = await authenticatedFetch('/api/vault');
                if (!vaultApiResponse.ok) throw new Error('Could not fetch user data to verify password.');
                const { vault: encryptedVault, salt: saltHex } = await vaultApiResponse.json();
                const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    
                // 2. Decrypt the vault with the old password to verify it's correct.
                let decryptedJson;
                try {
                    const oldKey = await deriveKey(oldPassword, salt);
                    if (encryptedVault) {
                        decryptedJson = await decrypt(encryptedVault, oldKey);
                    } else {
                        decryptedJson = '[]'; // Handle case for new user with no vault data yet.
                    }
                } catch (decryptionError) {
                    throw new Error('Incorrect old master password.');
                }
    
                // 3. Get final confirmation from the user.
                const confirmed = await showConfirm(
                    "Are you sure you want to change your master password? If you forget it, your data will be lost. This cannot be undone.",
                    "Change Master Password"
                );
                if (!confirmed) {
                    changePasswordStatus.textContent = 'Cancelled.';
                    changePasswordForm.reset();
                    return; // Stop if user cancels.
                }
    
                // 4. Re-encrypt the vault with the new password and save it.
                changePasswordStatus.textContent = 'Changing password...';
                const newKey = await deriveKey(newPassword, salt);
                const newEncryptedVault = await encrypt(decryptedJson, newKey);
    
                const saveResponse = await authenticatedFetch('/api/vault', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({ vault: newEncryptedVault })
                });
    
                if (!saveResponse.ok) {
                    throw new Error('Failed to save the re-encrypted vault.');
                }
    
                // 5. Success. Update UI.
                changePasswordStatus.textContent = 'Password changed successfully!';
                changePasswordStatus.style.color = 'green';
                changePasswordForm.reset();
    
                // If this action was performed on the vault page, update the in-memory key.
                if (encryptionKey) {
                    encryptionKey = newKey;
                }
    
            } catch (error) {
                console.error('Password change failed:', error);
                changePasswordStatus.textContent = error.message;
                changePasswordStatus.style.color = 'red';
            } finally {
                button.disabled = false;
                setTimeout(() => { changePasswordStatus.textContent = ''; }, 5000);
            }
        });
    }

    if (changeLoginPasswordForm) {
        changeLoginPasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('new-login-password').value;
            const statusEl = document.getElementById('login-password-status');
            const btn = changeLoginPasswordForm.querySelector('button');
            
            statusEl.textContent = 'Updating...';
            statusEl.style.color = 'inherit';
            btn.disabled = true;
            
            try {
                const response = await authenticatedFetch('/api/change_login_password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({ password: password })
                });
                
                const result = await response.json();
                if (response.ok) {
                    statusEl.textContent = 'Login password updated!';
                    statusEl.style.color = 'green';
                    document.getElementById('new-login-password').value = '';
                } else {
                    throw new Error(result.message || 'Failed to update password');
                }
            } catch (error) {
                statusEl.textContent = error.message;
                statusEl.style.color = 'red';
            } finally {
                btn.disabled = false;
                setTimeout(() => { statusEl.textContent = ''; }, 3000);
            }
        });
    }

    if (enable2faBtn) {
        enable2faBtn.addEventListener('click', async () => {
            const originalText = enable2faBtn.textContent;
            enable2faBtn.textContent = 'Enabling...';
            enable2faBtn.disabled = true;

            try {
                const response = await authenticatedFetch('/api/2fa/setup', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken }
                });
                const data = await response.json();
                if (data.status === 'success') {
                    document.getElementById('2fa-setup-section').classList.remove('hidden');
                    enable2faBtn.classList.add('hidden');

                    // Recalculate accordion panel height to fit new content
                    const panel = enable2faBtn.closest('.panel');
                    if (panel && panel.style.maxHeight) {
                        panel.style.maxHeight = panel.scrollHeight + "px";
                    }
                } else {
                    alert(data.message || 'Failed to initiate 2FA setup.');
                    enable2faBtn.textContent = originalText;
                    enable2faBtn.disabled = false;
                }
            } catch (error) {
                console.error('2FA Setup Error:', error);
                alert('Failed to start 2FA setup.');
                enable2faBtn.textContent = originalText;
                enable2faBtn.disabled = false;
            }
        });
    }

    if (verify2faForm) {
        verify2faForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const code = document.getElementById('verify-2fa-code').value;
            try {
                const response = await authenticatedFetch('/api/2fa/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                    body: JSON.stringify({ code: code })
                });
                const data = await response.json();
                if (data.status === 'success') {
                    await showAlert('Two-Factor Authentication Enabled!', 'Success');
                    window.location.reload();
                } else {
                    await showAlert(data.message || 'Invalid code.', 'Error');
                }
            } catch (error) {
                console.error('2FA Verify Error:', error);
            }
        });
    }

    if (resend2faBtn) {
        resend2faBtn.addEventListener('click', async () => {
            const msg = document.getElementById('2fa-msg');
            msg.textContent = 'Sending...';
            msg.style.color = 'inherit';
            resend2faBtn.disabled = true;
            
            try {
                // Re-use the setup endpoint to generate and send a new code
                const response = await authenticatedFetch('/api/2fa/setup', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken }
                });
                const data = await response.json();
                
                if (data.status === 'success') {
                    msg.textContent = 'Code resent!';
                    msg.style.color = 'green';
                } else {
                    msg.textContent = 'Failed to send.';
                    msg.style.color = 'red';
                }
            } catch (error) {
                console.error('Resend Error:', error);
                msg.textContent = 'Error.';
                msg.style.color = 'red';
            } finally {
                resend2faBtn.disabled = false;
                setTimeout(() => { if (msg.textContent === 'Code resent!') msg.textContent = ''; }, 3000);
            }
        });
    }

    if (disable2faBtn) {
        disable2faBtn.addEventListener('click', async () => {
            if (!await showConfirm('Are you sure you want to disable 2FA? Your account will be less secure.', 'Disable 2FA')) return;
            
            try {
                const response = await authenticatedFetch('/api/2fa/disable', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken }
                });
                if (response.ok) {
                    window.location.reload();
                }
            } catch (error) {
                console.error('2FA Disable Error:', error);
                alert('Failed to disable 2FA.');
            }
        });
    }
    
    if (deleteAccountBtn) {
        deleteAccountBtn.addEventListener('click', async () => {
            const confirmed = await showConfirm(
                "This will permanently delete your account and all stored data. This action cannot be undone. Are you sure?",
                "Delete Account"
            );
    
            if (!confirmed) return;
    
            try {
                const response = await authenticatedFetch('/api/account', {
                    method: 'DELETE',
                    headers: { 'X-CSRFToken': csrfToken }
                });
    
                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.message || 'Server error during account deletion.');
                }
    
                alert('Your account has been successfully deleted.');
                window.location.replace('/login');
            } catch (error) {
                console.error('Account deletion failed:', error);
                alert(`Failed to delete account: ${error.message}`);
            }
        });
    }

    if (entriesTableBody) {
        entriesTableBody.addEventListener('click', async (e) => {
        const target = e.target;

        // 1. Handle Copy Icon Button
        if (target.matches('.icon-copy-btn')) {
            const index = parseInt(target.dataset.index, 10);
            const entry = vaultData[index];
            copyToClipboard(entry.password, target);
            return;
        }

        // 2. Handle Password Text Click (Toggle)
        const passwordText = target.closest('.password-text');
        if (passwordText) {
            const cell = passwordText.closest('.password-cell');
            cell.classList.toggle('revealed');
            return;
        }

        // 3. Handle Action Buttons
        if (!target.matches('button.action-btn')) return;

        const action = target.dataset.action;
        const index = parseInt(target.dataset.index, 10);
        const entry = vaultData[index];

        if (action === 'edit') {
            startEditing(index);
        } else if (action === 'delete') {
            const confirmed = await showConfirm(`Are you sure you want to delete the entry for "${entry.site}"?`, 'Delete Entry');
            if (confirmed) {
                vaultData.splice(index, 1);
                
                // Adjust editing index if necessary
                if (editingIndex === index) {
                    cancelEditing();
                } else if (editingIndex !== null && editingIndex > index) {
                    editingIndex--;
                }
                
                renderVault();
                await saveVault();
            }
        }
    });
    }

    // --- Security Features ---

    /**
     * Copies text to the clipboard and clears it after 15 seconds.
     */
    function copyToClipboard(text, button) {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = button.textContent;
            
            if (button.classList.contains('icon-copy-btn')) {
                button.textContent = '✔️';
            } else {
                button.textContent = 'Copied';
            }

            button.disabled = true;
            // Security: Clear the clipboard after a delay to prevent accidental pasting.
            setTimeout(() => {
                // This is a best-effort attempt. It may not work in all browsers
                // or may be blocked by security settings.
                navigator.clipboard.writeText('').catch(err => console.warn('Could not clear clipboard:', err));
                button.textContent = originalText;
                button.disabled = false;
            }, 15000); // 15 seconds
        }).catch(err => {
            alert('Failed to copy password.');
            console.error('Clipboard copy failed:', err);
        });
    }

    /**
     * Resets the inactivity timer. Called on user interaction.
     */
    function resetInactivityTimer() {
        clearTimeout(inactivityTimer);
        // Auto-lock the vault after 5 minutes of inactivity.
        inactivityTimer = setTimeout(() => lockVault(true), 2 * 60 * 1000);
    }

    // Set up inactivity listeners
    ['mousemove', 'keydown', 'click', 'scroll'].forEach(event => {
        document.addEventListener(event, resetInactivityTimer);
    });

    /**
     * Simple HTML escaping to prevent XSS from stored data.
     */
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    // Accordion functionality
    const accordions = document.querySelectorAll('.accordion');
    accordions.forEach(acc => {
        acc.addEventListener('click', function() {
            this.classList.toggle('active');
            const panel = this.nextElementSibling;
            if (panel.style.maxHeight) {
                panel.style.maxHeight = null;
            } else {
                panel.style.maxHeight = panel.scrollHeight + "px";
            }
        });
    });
});
