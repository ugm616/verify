document.addEventListener('DOMContentLoaded', function() {
    const verifyBtn = document.getElementById('verifyBtn');
    const resultDiv = document.getElementById('result');
    
    verifyBtn.addEventListener('click', async function() {
        const email = document.getElementById('email').value.trim();
        const identifier = document.getElementById('identifier').value.trim();
        const code = document.getElementById('code').value.trim();
        
        // Basic validation
        if (!email || !identifier || !code) {
            showResult('All fields are required', false);
            return;
        }
        
        // Email validation
        if (!validateEmail(email)) {
            showResult('Please enter a valid email address', false);
            return;
        }
        
        // Identifier validation
        if (!/^\d{6}$/.test(identifier)) {
            showResult('Identifier must be 6 digits', false);
            return;
        }
        
        try {
            const response = await fetch('/api/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, identifier, code })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showResult('Verified user', true);
            } else {
                showResult(data.message || 'Unrecognised', false);
            }
        } catch (error) {
            showResult('Verification failed. Please try again.', false);
            console.error('Error:', error);
        }
    });
    
    function validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }
    
    function showResult(message, isSuccess) {
        resultDiv.textContent = message;
        resultDiv.classList.remove('hidden', 'success', 'error');
        resultDiv.classList.add(isSuccess ? 'success' : 'error');
    }
});