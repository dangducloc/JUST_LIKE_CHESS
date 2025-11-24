// Elements
const loginBtn       = document.getElementById('loginbtn');
const registerBtn     = document.getElementById('registerbtn');
const confirmationBtn = document.getElementById('confirmationbtn');

// Helper: Set button to loading state
function setButtonLoading(btn, loading = true) {
    if (!btn) return;

    if (loading) {
        btn.disabled = true;
        btn.dataset.originalText = btn.textContent;
        btn.textContent = 'Processing...';
        btn.classList.add('loading');
    } else {
        btn.disabled = false;
        btn.textContent = btn.dataset.originalText || 'Submit';
        btn.classList.remove('loading');
    }
}

// Reset button on error
function resetButton(btn) {
    if (btn) setButtonLoading(btn, false);
}

// Attach events based on current route
if (window.location.pathname === '/login' && loginBtn) {
    loginBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        if (loginBtn.disabled) return; // Prevent double click

        setButtonLoading(loginBtn);
        await loginUser();
    });
}

if (window.location.pathname === '/register' && registerBtn) {
    registerBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        if (registerBtn.disabled) return;

        setButtonLoading(registerBtn);
        await registerUser();
    });
}

if( window.location.pathname === '/confirm' && confirmationBtn) {
    confirmationBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        if (confirmationBtn.disabled) return;

        setButtonLoading(confirmationBtn);
        await confirmUser();
    });
}
// ==================== LOGIN ====================
async function loginUser() {
    const mail = document.getElementById('mail')?.value?.trim();
    const password = document.getElementById('password')?.value?.trim();

    if (!mail || !password) {
        alert('Please fill in all fields.');
        resetButton(loginBtn);
        return;
    }

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mail, password })
        });

        const data = await response.json();

        if (response.ok) {
            alert(data.message || 'Login successful!');
            window.location.href = '/dashboard';
            // No need to reset button — page will change
        } else {
            alert(data.message || 'Invalid email or password.');
            resetButton(loginBtn);
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Network error. Please try again later.');
        resetButton(loginBtn);
    }
}

// ==================== REGISTER ====================
async function registerUser() {
    const name = document.getElementById('username')?.value?.trim();
    const mail = document.getElementById('email')?.value?.trim();
    const password = document.getElementById('password')?.value?.trim();
    const confirmPassword = document.getElementById('confirm-password')?.value?.trim();

    if (!name || !mail || !password || !confirmPassword) {
        alert('Please fill in all fields.');
        resetButton(registerBtn);
        return;
    }

    if (password !== confirmPassword) {
        alert('Passwords do not match.');
        resetButton(registerBtn);
        return;
    }

    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, mail, password })
        });

        const data = await response.json();

        if (response.ok) {
            alert(data.message || 'Registration successful! Redirecting...');
            window.location.href = '/confirm';
        } else {
            alert(data.message || 'Registration failed. Please try again.');
            resetButton(registerBtn);
        }
    } catch (error) {
        console.error('Registration error:', error);
        alert('Network error. Please check your connection.');
        resetButton(registerBtn);
    }
}

//  ==================== CONFIRMATION ====================

confirmUser = async () => {
    const code = document.getElementById('token')?.value?.trim();

    if (!code) {
        alert('Please enter the confirmation token.');
        resetButton(confirmationBtn);
        return;
    }

    try {
        const response = await fetch(`/api/auth/confirm/${code}`, {
            method: 'GET'
        });

        const data = await response.json();

        if (response.ok) {
            alert(data.message || 'Account confirmed! Redirecting to login...');
            window.location.href = '/login';
        } else {
            alert(data.message || 'Invalid confirmation code.');
            resetButton(confirmationBtn);
        }
    } catch (error) {
        console.error('Confirmation error:', error);
        alert('Network error. Please try again later.');
        resetButton(confirmationBtn);
    }
}

