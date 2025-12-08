// Form validation functionality for AI Learning Platform

document.addEventListener('DOMContentLoaded', function() {
    // Email validation regex
    const emailRegex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    
    // Password strength regex patterns
    const passwordPatterns = {
        lowercase: /[a-z]/,
        uppercase: /[A-Z]/,
        digit: /[0-9]/,
        special: /[^A-Za-z0-9]/,
        length: /.{8,}/
    };
    
    // Initialize validation for login form
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            let isValid = true;
            
            // Validate email
            const emailInput = document.getElementById('email');
            const emailErrorContainer = emailInput?.closest('.mb-3')?.querySelector('.form-text.text-danger');
            
            if (emailInput && !emailRegex.test(emailInput.value.trim())) {
                if (emailErrorContainer) emailErrorContainer.textContent = 'Please enter a valid email address';
                emailInput.classList.add('is-invalid');
                isValid = false;
            } else if (emailInput) {
                emailInput.classList.remove('is-invalid');
                if (emailErrorContainer) emailErrorContainer.textContent = '';
            }
            
            // Validate password (just check if not empty for login)
            const passwordInput = document.getElementById('password');
            const passwordErrorContainer = passwordInput?.closest('.mb-3')?.querySelector('.form-text.text-danger');
            
            if (passwordInput && passwordInput.value.trim() === '') {
                if (passwordErrorContainer) passwordErrorContainer.textContent = 'Password is required';
                passwordInput.classList.add('is-invalid');
                isValid = false;
            } else if (passwordInput) {
                passwordInput.classList.remove('is-invalid');
                if (passwordErrorContainer) passwordErrorContainer.textContent = '';
            }
            
            if (!isValid) {
                e.preventDefault();
            }
        });
    }
    
    // Initialize validation for registration form
    const registrationForm = document.getElementById('registration-form');
    if (registrationForm) {
        // Password strength meter
        const passwordInput = document.getElementById('password');
        const strengthMeter = document.getElementById('password-strength-meter');
        const strengthText = document.getElementById('password-strength-text');
        
        if (passwordInput && strengthMeter && strengthText) {
            passwordInput.addEventListener('input', function() {
                const password = this.value;
                let strength = 0;
                let feedback = [];
                
                // Check each criteria
                if (passwordPatterns.lowercase.test(password)) strength += 1;
                else feedback.push('lowercase letter');
                
                if (passwordPatterns.uppercase.test(password)) strength += 1;
                else feedback.push('uppercase letter');
                
                if (passwordPatterns.digit.test(password)) strength += 1;
                else feedback.push('number');
                
                if (passwordPatterns.special.test(password)) strength += 1;
                else feedback.push('special character');
                
                if (passwordPatterns.length.test(password)) strength += 1;
                else feedback.push('minimum length of 8 characters');
                
                // Update the strength meter - now using a progress-bar element
                if (strengthMeter) {
                    if (password === '') {
                        strengthMeter.style.width = '0';
                        strengthMeter.className = 'progress-bar';
                        strengthText.textContent = '';
                    } else if (strength < 2) {
                        strengthMeter.style.width = '25%';
                        strengthMeter.className = 'progress-bar bg-danger';
                        strengthText.textContent = 'Weak password';
                    } else if (strength < 4) {
                        strengthMeter.style.width = '50%';
                        strengthMeter.className = 'progress-bar bg-warning';
                        strengthText.textContent = 'Medium strength password';
                    } else if (strength < 5) {
                        strengthMeter.style.width = '75%';
                        strengthMeter.className = 'progress-bar bg-info';
                        strengthText.textContent = 'Strong password';
                    } else {
                        strengthMeter.style.width = '100%';
                        strengthMeter.className = 'progress-bar bg-success';
                        strengthText.textContent = 'Very strong password';
                    }
                    
                    // Show feedback if not very strong
                    if (strength < 5 && feedback.length > 0) {
                        strengthText.textContent += ': Add ' + feedback.join(', ');
                    }
                }
            });
        }
        
        // Validate on form submit
        registrationForm.addEventListener('submit', function(e) {
            let isValid = true;
            
            // Validate username
            const usernameInput = document.getElementById('username');
            const usernameErrorContainer = usernameInput?.closest('.mb-3')?.querySelector('.form-text.text-danger');
            const usernameRegex = /^[A-Za-z][A-Za-z0-9_.]*$/;
            
            if (usernameInput) {
                if (usernameInput.value.trim() === '') {
                    if (usernameErrorContainer) usernameErrorContainer.textContent = 'Username is required';
                    usernameInput.classList.add('is-invalid');
                    isValid = false;
                } else if (usernameInput.value.length < 3) {
                    if (usernameErrorContainer) usernameErrorContainer.textContent = 'Username must be at least 3 characters';
                    usernameInput.classList.add('is-invalid');
                    isValid = false;
                } else if (!usernameRegex.test(usernameInput.value)) {
                    if (usernameErrorContainer) usernameErrorContainer.textContent = 'Username must start with a letter and can only contain letters, numbers, dots or underscores';
                    usernameInput.classList.add('is-invalid');
                    isValid = false;
                } else {
                    usernameInput.classList.remove('is-invalid');
                    if (usernameErrorContainer) usernameErrorContainer.textContent = '';
                }
            }
            
            // Validate email
            const emailInput = document.getElementById('email');
            const emailErrorContainer = emailInput?.closest('.mb-3')?.querySelector('.form-text.text-danger');
            
            if (emailInput && !emailRegex.test(emailInput.value.trim())) {
                if (emailErrorContainer) emailErrorContainer.textContent = 'Please enter a valid email address';
                emailInput.classList.add('is-invalid');
                isValid = false;
            } else if (emailInput) {
                emailInput.classList.remove('is-invalid');
                if (emailErrorContainer) emailErrorContainer.textContent = '';
            }
            
            // Validate password
            const passwordInput = document.getElementById('password');
            const passwordErrorContainer = passwordInput?.closest('.mb-3')?.querySelector('.form-text.text-danger');
            
            if (passwordInput) {
                const password = passwordInput.value;
                let passwordValid = true;
                
                if (!passwordPatterns.lowercase.test(password) || 
                    !passwordPatterns.uppercase.test(password) || 
                    !passwordPatterns.digit.test(password) || 
                    !passwordPatterns.length.test(password)) {
                    passwordValid = false;
                }
                
                if (!passwordValid) {
                    if (passwordErrorContainer) passwordErrorContainer.textContent = 'Password must be at least 8 characters and include uppercase, lowercase, and numbers';
                    passwordInput.classList.add('is-invalid');
                    isValid = false;
                } else {
                    passwordInput.classList.remove('is-invalid');
                    if (passwordErrorContainer) passwordErrorContainer.textContent = '';
                }
            }
            
            // Validate password confirmation
            const password2Input = document.getElementById('password2');
            const password2ErrorContainer = password2Input?.closest('.mb-3')?.querySelector('.form-text.text-danger');
            
            if (passwordInput && password2Input && passwordInput.value !== password2Input.value) {
                if (password2ErrorContainer) password2ErrorContainer.textContent = 'Passwords do not match';
                password2Input.classList.add('is-invalid');
                isValid = false;
            } else if (password2Input) {
                password2Input.classList.remove('is-invalid');
                if (password2ErrorContainer) password2ErrorContainer.textContent = '';
            }
            
            if (!isValid) {
                e.preventDefault();
            }
        });
    }
    
    // Initialize validation for 2FA form
    const twoFactorForm = document.getElementById('two-factor-form');
    if (twoFactorForm) {
        const tokenInput = document.getElementById('token');
        const tokenErrorContainer = tokenInput?.closest('.mb-3')?.querySelector('.form-text.text-danger');
        
        twoFactorForm.addEventListener('submit', function(e) {
            let isValid = true;
            
            if (tokenInput) {
                const tokenRegex = /^\d{6}$/;
                if (!tokenRegex.test(tokenInput.value.trim())) {
                    if (tokenErrorContainer) tokenErrorContainer.textContent = 'Authentication code must be 6 digits';
                    tokenInput.classList.add('is-invalid');
                    isValid = false;
                } else {
                    tokenInput.classList.remove('is-invalid');
                    if (tokenErrorContainer) tokenErrorContainer.textContent = '';
                }
            }
            
            if (!isValid) {
                e.preventDefault();
            }
        });
        
        // Auto-focus and format token input
        if (tokenInput) {
            tokenInput.focus();
            
            tokenInput.addEventListener('input', function() {
                // Remove non-digits
                this.value = this.value.replace(/\D/g, '');
                
                // Limit to 6 digits
                if (this.value.length > 6) {
                    this.value = this.value.slice(0, 6);
                }
            });
            
            // Auto-submit when 6 digits are entered
            tokenInput.addEventListener('keyup', function() {
                if (this.value.length === 6) {
                    // Check if the form is valid
                    const tokenRegex = /^\d{6}$/;
                    if (tokenRegex.test(this.value)) {
                        twoFactorForm.submit();
                    }
                }
            });
        }
    }
    
    // Initialize live validation for forms
    document.querySelectorAll('input, textarea, select').forEach(input => {
        // Skip submit buttons
        if (input.type === 'submit' || input.type === 'button') return;
        
        input.addEventListener('blur', function() {
            validateInput(this);
        });
    });
    
    // Validate a single input field
    function validateInput(input) {
        // Skip validation if field is empty and not required
        if (input.value.trim() === '' && !input.hasAttribute('required')) {
            input.classList.remove('is-invalid');
            const errorContainer = input?.closest('.mb-3')?.querySelector('.form-text.text-danger');
            if (errorContainer) errorContainer.textContent = '';
            return;
        }
        
        // Different validation based on input type
        switch(input.type) {
            case 'email':
                validateEmail(input);
                break;
            case 'password':
                // Don't validate on blur for password fields
                break;
            case 'text':
                if (input.id === 'username') {
                    validateUsername(input);
                }
                break;
            // Add more cases for other input types as needed
        }
    }
    
    // Email validation helper
    function validateEmail(input) {
        const errorContainer = input?.closest('.mb-3')?.querySelector('.form-text.text-danger');
        
        if (!emailRegex.test(input.value.trim())) {
            input.classList.add('is-invalid');
            if (errorContainer) errorContainer.textContent = 'Please enter a valid email address';
        } else {
            input.classList.remove('is-invalid');
            if (errorContainer) errorContainer.textContent = '';
        }
    }
    
    // Username validation helper
    function validateUsername(input) {
        const errorContainer = input?.closest('.mb-3')?.querySelector('.form-text.text-danger');
        const usernameRegex = /^[A-Za-z][A-Za-z0-9_.]*$/;
        
        if (input.value.trim() === '') {
            input.classList.add('is-invalid');
            if (errorContainer) errorContainer.textContent = 'Username is required';
        } else if (input.value.length < 3) {
            input.classList.add('is-invalid');
            if (errorContainer) errorContainer.textContent = 'Username must be at least 3 characters';
        } else if (!usernameRegex.test(input.value)) {
            input.classList.add('is-invalid');
            if (errorContainer) errorContainer.textContent = 'Username must start with a letter and can only contain letters, numbers, dots or underscores';
        } else {
            input.classList.remove('is-invalid');
            if (errorContainer) errorContainer.textContent = '';
        }
    }
});
