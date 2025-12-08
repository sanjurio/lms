// Floating Chat Functionality
document.addEventListener('DOMContentLoaded', function() {
    const chatIcon = document.getElementById('floating-chat-icon');
    const chatPopup = document.getElementById('document-chat-popup');
    const closeBtn = document.getElementById('close-chat-btn');
    const documentUploadForm = document.getElementById('document-upload-form');
    
    if (chatIcon && chatPopup) {
        const apiKeyStatus = document.getElementById('api-key-status');
        const analyzeBtn = document.getElementById('analyze-btn');
        
        // Function to check API key status
        function checkApiKeyStatus() {
            if (!apiKeyStatus) return;
            
            // Show loading state
            apiKeyStatus.innerHTML = `
                <div class="spinner-border spinner-border-sm text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <span class="ms-2">Checking API configuration...</span>
            `;
            
            // Determine which endpoint to use based on admin status
            const endpoint = document.querySelector('body').classList.contains('admin') ? 
                '/api/test-openai-connection' : '/api/check-api-config';
                
            // Fetch API key status from server
            fetch(endpoint)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // API key is configured and working
                        apiKeyStatus.innerHTML = `
                            <div class="alert alert-success py-2 small mb-0">
                                <i class="bi bi-check-circle me-2"></i>
                                API connection is working correctly.
                            </div>
                        `;
                        if (analyzeBtn) analyzeBtn.disabled = false;
                    } else {
                        // API key is not configured or not working
                        apiKeyStatus.innerHTML = `
                            <div class="alert alert-warning py-2 small mb-0">
                                <i class="bi bi-exclamation-triangle me-2"></i>
                                <strong>API connection issue:</strong>
                                <p class="mb-0 mt-1">${data.message || 'The OpenAI API is not configured correctly.'}</p>
                                ${document.querySelector('body').classList.contains('admin') ? 
                                    '<p class="mb-0 mt-1">Please go to <a href="/admin/api-keys">API Keys</a> page to configure it.</p>' : 
                                    '<p class="mb-0 mt-1">Please contact an administrator to configure the API.</p>'}
                            </div>
                        `;
                        if (analyzeBtn) analyzeBtn.disabled = true;
                    }
                })
                .catch(error => {
                    // Error checking API key status
                    apiKeyStatus.innerHTML = `
                        <div class="alert alert-danger py-2 small mb-0">
                            <i class="bi bi-x-circle me-2"></i>
                            <strong>Error checking API status:</strong>
                            <p class="mb-0 mt-1">${error.message || 'An error occurred while checking the API connection.'}</p>
                        </div>
                    `;
                    if (analyzeBtn) analyzeBtn.disabled = true;
                });
        }
        
        // Toggle chat popup when clicking the floating icon
        chatIcon.addEventListener('click', function() {
            const wasHidden = !chatPopup.classList.contains('show');
            chatPopup.classList.toggle('show');
            
            // Check API key status when opening the popup
            if (wasHidden && apiKeyStatus) {
                checkApiKeyStatus();
            }
        });
        
        // Close chat popup when clicking the close button
        if (closeBtn) {
            closeBtn.addEventListener('click', function() {
                chatPopup.classList.remove('show');
            });
        }
        
        // Close popup when clicking outside of it (optional)
        document.addEventListener('click', function(event) {
            if (!chatPopup.contains(event.target) && 
                !chatIcon.contains(event.target) && 
                chatPopup.classList.contains('show')) {
                chatPopup.classList.remove('show');
            }
        });
    }
    
    // Document upload and analysis functionality
    if (documentUploadForm) {
        const fileInput = document.getElementById('document-file');
        const analyzeBtn = document.getElementById('analyze-btn');
        const loadingSpinner = document.getElementById('loading-spinner');
        const resultsSection = document.getElementById('results-section');
        const summaryContent = document.getElementById('summary-content');
        const questionsContent = document.getElementById('questions-content');
        
        documentUploadForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (!fileInput.files.length) {
                alert('Please select a file to analyze');
                return;
            }
            
            // Show loading state
            loadingSpinner.classList.remove('d-none');
            analyzeBtn.disabled = true;
            resultsSection.classList.add('d-none');
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            fetch('/api/analyze-document', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                // First check if it's a valid JSON response
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    return response.json().then(data => {
                        if (!response.ok) {
                            throw new Error(data.message || 'An error occurred while analyzing the document');
                        }
                        return data;
                    });
                } else {
                    // Not a JSON response, likely an HTML error page
                    return response.text().then(text => {
                        console.error('Received non-JSON response:', text.substring(0, 200) + '...');
                        throw new Error('The server returned an invalid response. Please try again or contact an administrator.');
                    });
                }
            })
            .then(data => {
                // Hide loading state
                loadingSpinner.classList.add('d-none');
                analyzeBtn.disabled = false;
                
                // Show results
                resultsSection.classList.remove('d-none');
                
                // Display summary
                if (summaryContent) {
                    summaryContent.textContent = data.summary || 'No summary generated';
                }
                
                // Display questions
                if (questionsContent) {
                    questionsContent.innerHTML = '';
                    if (data.questions && data.questions.length) {
                        const accordion = document.createElement('div');
                        accordion.className = 'accordion';
                        accordion.id = 'questionsAccordion';
                        
                        data.questions.forEach((qa, index) => {
                            const itemId = `question-${index}`;
                            const collapseId = `collapse-${index}`;
                            
                            const accordionItem = document.createElement('div');
                            accordionItem.className = 'accordion-item';
                            
                            accordionItem.innerHTML = `
                                <h2 class="accordion-header" id="${itemId}">
                                    <button class="accordion-button ${index > 0 ? 'collapsed' : ''}" type="button" 
                                            data-bs-toggle="collapse" data-bs-target="#${collapseId}" 
                                            aria-expanded="${index === 0 ? 'true' : 'false'}" aria-controls="${collapseId}">
                                        ${qa.question}
                                    </button>
                                </h2>
                                <div id="${collapseId}" class="accordion-collapse collapse ${index === 0 ? 'show' : ''}" 
                                     aria-labelledby="${itemId}" data-bs-parent="#questionsAccordion">
                                    <div class="accordion-body">
                                        ${qa.answer}
                                    </div>
                                </div>
                            `;
                            
                            accordion.appendChild(accordionItem);
                        });
                        
                        questionsContent.appendChild(accordion);
                    } else {
                        questionsContent.innerHTML = '<p>No questions generated</p>';
                    }
                }
            })
            .catch(error => {
                // Hide loading state
                loadingSpinner.classList.add('d-none');
                analyzeBtn.disabled = false;
                
                // Show error in a nicer way
                resultsSection.classList.remove('d-none');
                
                if (summaryContent) {
                    summaryContent.innerHTML = `
                        <div class="alert alert-danger">
                            <strong>Error:</strong> ${error.message || 'An error occurred while analyzing the document'}
                        </div>
                        <div class="mt-3">
                            <p>Possible solutions:</p>
                            <ul>
                                <li>Make sure the OpenAI API key is configured correctly in the admin panel</li>
                                <li>Check that the file format is supported (PDF, DOCX, or TXT)</li>
                                <li>Try a different document if the problem persists</li>
                                <li>Contact an administrator for assistance</li>
                            </ul>
                        </div>
                    `;
                }
                
                if (questionsContent) {
                    questionsContent.innerHTML = '';
                }
            });
        });
    }
    
    // API connection test functionality
    const testConnectionBtn = document.getElementById('test-connection-btn');
    const connectionTestResults = document.getElementById('connection-test-results');
    const connectionTestOutput = connectionTestResults ? connectionTestResults.querySelector('pre') : null;
    
    if (testConnectionBtn && connectionTestResults && connectionTestOutput) {
        testConnectionBtn.addEventListener('click', function() {
            // Show loading state
            testConnectionBtn.disabled = true;
            testConnectionBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Testing...';
            
            // Make API request to test connection
            fetch('/api/test-openai-connection')
                .then(response => response.json())
                .then(data => {
                    // Format the JSON response for display
                    connectionTestOutput.textContent = JSON.stringify(data, null, 2);
                    
                    // Show the results and color-code based on success/failure
                    connectionTestResults.classList.remove('d-none');
                    
                    if (data.success) {
                        connectionTestOutput.classList.add('text-success');
                        connectionTestOutput.classList.remove('text-danger');
                    } else {
                        connectionTestOutput.classList.add('text-danger');
                        connectionTestOutput.classList.remove('text-success');
                    }
                })
                .catch(error => {
                    // Show error
                    connectionTestResults.classList.remove('d-none');
                    connectionTestOutput.classList.add('text-danger');
                    connectionTestOutput.classList.remove('text-success');
                    connectionTestOutput.textContent = `Error running test: ${error.message}`;
                })
                .finally(() => {
                    // Reset button state
                    testConnectionBtn.disabled = false;
                    testConnectionBtn.textContent = 'Test API Connection';
                });
        });
    }
});