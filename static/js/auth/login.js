document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const messageDiv = document.getElementById('message');
    const submitBtn = this.querySelector('button[type="submit"]');

    // Clear previous messages
    messageDiv.style.display = 'none';
    messageDiv.className = 'message';

    // Get form data
    const formData = new FormData(this);
    const data = {
        mail: formData.get('mail').trim(),
        password: formData.get('password')
    };

    // Basic validation
    if (!data.mail || !data.password) {
        showMessage('Please fill in all fields', 'error');
        return;
    }

    // Disable button
    submitBtn.disabled = true;
    submitBtn.textContent = 'Logging in...';

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include', // Include cookies
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (response.ok) {
            showMessage('Login successful! Redirecting...', 'success');
            // Redirect to home page
            setTimeout(() => {
                window.location.href = '/home'; 
            }, 1000);
        } else {
            showMessage(result.message || 'Login failed', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        showMessage('Network error. Please try again.', 'error');
    } finally {
        // Re-enable button
        submitBtn.disabled = false;
        submitBtn.textContent = 'Login';
    }
});

function showMessage(message, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;
    messageDiv.style.display = 'block';
}
