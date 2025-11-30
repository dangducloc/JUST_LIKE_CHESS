
// DOM Elements
const manualConfirmForm = document.getElementById('manualConfirmForm');
const tokenInput = document.getElementById('tokenInput');
const confirmBtn = document.getElementById('confirmBtn');
const btnSpinner = document.getElementById('btnSpinner');
const messageDiv = document.getElementById('message');

// Handle manual confirmation form
manualConfirmForm.addEventListener('submit', async function(e) {
    e.preventDefault();

    const token = tokenInput.value.trim();

    if (!token) {
        showMessage('Please enter a confirmation token', 'error');
        return;
    }

    // Show loading state
    setLoadingState(true);

    try {
        const response = await fetch(`/api/auth/confirm/${token}`, {
            method: 'GET',
        });

        const result = await response.json();

        if (response.ok) {
            showMessage('Email confirmed successfully! Redirecting to login...', 'success');
            // Redirect to login after success
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else {
            showMessage(result.message || 'Confirmation failed. Please check your token.', 'error');
        }
    } catch (error) {
        console.error('Confirmation error:', error);
        showMessage('Network error. Please try again.', 'error');
    } finally {
        setLoadingState(false);
    }
});

function setLoadingState(loading) {
    confirmBtn.disabled = loading;
    btnSpinner.classList.toggle('show', loading);

    const btnText = confirmBtn.querySelector('.btn-text');
    if (loading) {
        btnText.textContent = 'Confirming...';
    } else {
        btnText.textContent = 'Confirm Email';
    }
}

function showMessage(message, type) {
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;
    messageDiv.style.display = 'block';

    // Scroll to message
    messageDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
