// DOM Elements
const registerForm = document.getElementById('registerForm');
const nameInput = document.getElementById('name');
const mailInput = document.getElementById('mail');
const passwordInput = document.getElementById('password');
const confirmPasswordInput = document.getElementById('confirmPassword');

const registerBtn = document.getElementById('registerBtn');
const btnSpinner = document.getElementById('btnSpinner');
const passwordToggle = document.getElementById('passwordToggle');
const strengthBar = document.getElementById('strengthBar');
const strengthText = document.getElementById('strengthText');

// Error message elements
const nameError = document.getElementById('nameError');
const mailError = document.getElementById('mailError');
const passwordError = document.getElementById('passwordError');
const confirmPasswordError = document.getElementById('confirmPasswordError');

// Password visibility toggle
passwordToggle.addEventListener('click', function() {
    const type = passwordInput.type === 'password' ? 'text' : 'password';
    passwordInput.type = type;
    this.querySelector('.eye-icon').textContent = type === 'password' ? '👁️' : '🙈';
});

// Password strength checker
passwordInput.addEventListener('input', function() {
    const password = this.value;
    const strength = checkPasswordStrength(password);
    updatePasswordStrength(strength);
});

function checkPasswordStrength(password) {
    let score = 0;

    // Length check
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;

    // Character variety
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    return score;
}

function updatePasswordStrength(score) {
    const strengthMeter = strengthBar.parentElement.parentElement;

    // Remove existing classes
    strengthMeter.classList.remove('strength-weak', 'strength-medium', 'strength-strong');

    if (score < 3) {
        strengthMeter.classList.add('strength-weak');
        strengthText.textContent = 'Weak password';
    } else if (score < 5) {
        strengthMeter.classList.add('strength-medium');
        strengthText.textContent = 'Medium password';
    } else {
        strengthMeter.classList.add('strength-strong');
        strengthText.textContent = 'Strong password';
    }
}

// Real-time validation
nameInput.addEventListener('blur', () => validateName());
mailInput.addEventListener('blur', () => validateEmail());
passwordInput.addEventListener('blur', () => validatePassword());
confirmPasswordInput.addEventListener('blur', () => validateConfirmPassword());

function validateName() {
    const name = nameInput.value.trim();
    if (!name) {
        showError(nameError, 'Name is required');
        return false;
    }
    if (name.length < 2) {
        showError(nameError, 'Name must be at least 2 characters');
        return false;
    }
    if (name.length > 50) {
        showError(nameError, 'Name must be less than 50 characters');
        return false;
    }
    hideError(nameError);
    return true;
}

function validateEmail() {
    const email = mailInput.value.trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!email) {
        showError(mailError, 'Email is required');
        return false;
    }
    if (!emailRegex.test(email)) {
        showError(mailError, 'Please enter a valid email address');
        return false;
    }
    hideError(mailError);
    return true;
}

function validatePassword() {
    const password = passwordInput.value;

    if (!password) {
        showError(passwordError, 'Password is required');
        return false;
    }
    if (password.length < 8) {
        showError(passwordError, 'Password must be at least 8 characters');
        return false;
    }

    // Check for at least one lowercase, one uppercase, one number
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);

    if (!hasLower || !hasUpper || !hasNumber) {
        showError(passwordError, 'Password must contain at least one lowercase letter, one uppercase letter, and one number');
        return false;
    }

    hideError(passwordError);
    return true;
}

function validateConfirmPassword() {
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (!confirmPassword) {
        showError(confirmPasswordError, 'Please confirm your password');
        return false;
    }
    if (password !== confirmPassword) {
        showError(confirmPasswordError, 'Passwords do not match');
        return false;
    }
    hideError(confirmPasswordError);
    return true;
}

function validateTerms() {
    if (!termsCheckbox.checked) {
        showError(document.querySelector('.terms-group'), 'You must agree to the Terms of Service and Privacy Policy');
        return false;
    }
    hideError(document.querySelector('.terms-group'));
    return true;
}

function showError(element, message) {
    element.textContent = message;
    element.style.display = 'block';
    element.parentElement.classList.add('error');
}

function hideError(element) {
    element.textContent = '';
    element.style.display = 'none';
    element.parentElement.classList.remove('error');
}

// Form submission
registerForm.addEventListener('submit', async function(e) {
    e.preventDefault();

    // Validate all fields
    const isNameValid = validateName();
    const isEmailValid = validateEmail();
    const isPasswordValid = validatePassword();
    const isConfirmPasswordValid = validateConfirmPassword();

    if (!isNameValid || !isEmailValid || !isPasswordValid || !isConfirmPasswordValid) {
        showMessage('Please correct the errors above', 'error');
        return;
    }

    // Show loading state
    setLoadingState(true);

    // Prepare data
    const formData = {
        name: nameInput.value.trim(),
        mail: mailInput.value.trim().toLowerCase(),
        password: passwordInput.value
    };

    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });

        const result = await response.json();

        if (response.ok) {
            showMessage('Registration successful! Please check your email to confirm your account.', 'success');

            // Clear form
            registerForm.reset();

            // Reset password strength
            updatePasswordStrength(0);

            // Redirect to confirm after success
            setTimeout(() => {
                window.location.href = '/confirm';
            }, 3000);

        } else {
            showMessage(result.message || 'Registration failed', 'error');
        }
    } catch (error) {
        console.error('Registration error:', error);
        showMessage('Network error. Please try again.', 'error');
    } finally {
        setLoadingState(false);
    }
});

function setLoadingState(loading) {
    registerBtn.disabled = loading;
    btnSpinner.classList.toggle('show', loading);

    const btnText = registerBtn.querySelector('.btn-text');
    if (loading) {
        btnText.textContent = 'Creating Account...';
    } else {
        btnText.textContent = 'Create Account';
    }
}

function showMessage(message, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;
    messageDiv.style.display = 'block';

    // Scroll to message
    messageDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Initialize password strength on page load
updatePasswordStrength(0);
