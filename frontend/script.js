// Enhanced JavaScript for CerebralGuard Frontend

class CerebralGuardUI {
    constructor() {
        this.API_BASE_URL = 'http://localhost:8000';
        this.notifications = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.createParticles();
        this.initializeAnimations();
        this.updateDashboard();
    }

    setupEventListeners() {
        // Mobile menu toggle
        const mobileMenuBtn = document.getElementById('mobile-menu-btn');
        const mobileMenu = document.getElementById('mobile-menu');
        
        if (mobileMenuBtn && mobileMenu) {
            mobileMenuBtn.addEventListener('click', () => {
                mobileMenu.classList.toggle('hidden');
            });
        }

        // Form submission
        const emailForm = document.getElementById('emailForm');
        if (emailForm) {
            emailForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.processEmail();
            });
        }

        // Smooth scrolling for navigation links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', (e) => {
                e.preventDefault();
                const target = document.querySelector(anchor.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });

        // Intersection Observer for animations
        this.setupIntersectionObserver();
    }

    createParticles() {
        const heroSection = document.querySelector('#home');
        if (!heroSection) return;

        const particlesContainer = document.createElement('div');
        particlesContainer.className = 'particles';
        heroSection.appendChild(particlesContainer);

        for (let i = 0; i < 20; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.style.left = Math.random() * 100 + '%';
            particle.style.animationDelay = Math.random() * 6 + 's';
            particle.style.animationDuration = (Math.random() * 3 + 3) + 's';
            particlesContainer.appendChild(particle);
        }
    }

    setupIntersectionObserver() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('fade-in');
                    
                    // Add staggered animations for cards
                    if (entry.target.classList.contains('card-hover')) {
                        const cards = entry.target.parentElement.querySelectorAll('.card-hover');
                        cards.forEach((card, index) => {
                            setTimeout(() => {
                                card.classList.add('slide-up');
                            }, index * 100);
                        });
                    }
                }
            });
        }, observerOptions);

        // Observe all cards and sections
        document.querySelectorAll('.card-hover, section').forEach(el => {
            observer.observe(el);
        });
    }

    initializeAnimations() {
        // Typing effect for hero title
        const typingElement = document.querySelector('.typing-effect');
        if (typingElement) {
            const text = typingElement.textContent;
            typingElement.textContent = '';
            let i = 0;
            
            const typeWriter = () => {
                if (i < text.length) {
                    typingElement.textContent += text.charAt(i);
                    i++;
                    setTimeout(typeWriter, 100);
                }
            };
            
            setTimeout(typeWriter, 1000);
        }

        // Animate statistics on scroll
        this.animateStatistics();
    }

    animateStatistics() {
        const statsElements = document.querySelectorAll('[id$="Count"], [id="totalEmails"]');
        
        const animateValue = (element, targetValue) => {
            const currentValue = parseInt(element.textContent) || 0;
            const increment = (targetValue - currentValue) / 30;
            let current = currentValue;
            
            const timer = setInterval(() => {
                current += increment;
                if ((increment > 0 && current >= targetValue) || (increment < 0 && current <= targetValue)) {
                    element.textContent = targetValue;
                    clearInterval(timer);
                } else {
                    element.textContent = Math.floor(current);
                }
            }, 50);
        };

        // Animate when elements come into view
        const statsObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const targetValue = parseInt(entry.target.getAttribute('data-target')) || 0;
                    animateValue(entry.target, targetValue);
                    statsObserver.unobserve(entry.target);
                }
            });
        });

        statsElements.forEach(el => {
            statsObserver.observe(el);
        });
    }

    async processEmail() {
        const emailContent = document.getElementById('emailContent').value.trim();
        if (!emailContent) {
            this.showNotification('Please enter email content to analyze', 'error');
            return;
        }

        this.showLoading();
        this.showNotification('Processing email with AI...', 'warning');

        try {
            const response = await fetch(`${this.API_BASE_URL}/process-email`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email_content: emailContent
                })
            });

            if (response.ok) {
                const data = await response.json();
                if (data.success) {
                    this.showResults(data);
                    this.showNotification('Analysis completed successfully!', 'success');
                } else {
                    this.showError(data.error || 'Analysis failed');
                    this.showNotification('Analysis failed', 'error');
                }
            } else {
                const errorData = await response.json();
                this.showError(errorData.detail || 'Server error');
                this.showNotification('Server error occurred', 'error');
            }
        } catch (error) {
            this.showError('Network error. Please check if the API is running.');
            this.showNotification('Network error', 'error');
        }
    }

    showLoading() {
        document.getElementById('loadingResults').classList.remove('hidden');
        document.getElementById('resultsDisplay').classList.add('hidden');
        document.getElementById('errorDisplay').classList.add('hidden');
    }

    hideLoading() {
        document.getElementById('loadingResults').classList.add('hidden');
    }

    showResults(data) {
        this.hideLoading();
        const resultsDisplay = document.getElementById('resultsDisplay');
        resultsDisplay.classList.remove('hidden');
        resultsDisplay.classList.add('bounce-in');

        // Update verdict with enhanced styling
        const verdict = data.final_analysis.verdict;
        const verdictElement = document.getElementById('verdict');
        verdictElement.textContent = verdict.toUpperCase();
        verdictElement.className = `text-2xl font-bold verdict-${verdict} zoom-in`;

        // Update confidence with animated progress bar
        const confidence = data.final_analysis.confidence || 'medium';
        const confidencePercent = confidence === 'high' ? 90 : confidence === 'medium' ? 70 : 50;
        const confidenceBar = document.getElementById('confidenceBar');
        const confidenceText = document.getElementById('confidenceText');

        setTimeout(() => {
            confidenceBar.style.width = `${confidencePercent}%`;
            confidenceText.textContent = `${confidencePercent}%`;
            confidenceBar.classList.add('progress-bar-enhanced');
        }, 500);

        // Update summary
        document.getElementById('summary').textContent = data.final_analysis.summary || 'No summary available';

        // Update processing time
        document.getElementById('processingTime').textContent = `${data.processing_time.toFixed(2)} seconds`;

        // Update dashboard
        this.updateDashboard();
    }

    showError(message) {
        this.hideLoading();
        document.getElementById('errorDisplay').classList.remove('hidden');
        document.getElementById('errorMessage').textContent = message;
    }

    loadSampleEmail() {
        const sampleEmail = `From: security@microsoft-support.com
Subject: URGENT: Your Microsoft Account Has Been Compromised
Date: Mon, 15 Jan 2024 10:30:00 +0000

Dear Microsoft User,

We have detected suspicious activity on your Microsoft account. Your account has been temporarily suspended for security reasons.

To restore access to your account immediately, please click the link below and verify your identity:

https://microsoft-verify.secure-login.com/account/verify

If you do not verify within 24 hours, your account will be permanently deleted.

This is an automated security message. Please do not reply to this email.

Microsoft Security Team`;

        document.getElementById('emailContent').value = sampleEmail;
        this.showNotification('Sample email loaded', 'success');
    }

    async updateDashboard() {
        try {
            const response = await fetch(`${this.API_BASE_URL}/statistics`);
            const stats = await response.json();

            // Animate number changes
            this.animateNumber('totalEmails', stats.total_processed);
            this.animateNumber('maliciousCount', stats.malicious_count);
            this.animateNumber('suspiciousCount', stats.suspicious_count);
            this.animateNumber('safeCount', stats.safe_count);

        } catch (error) {
            console.error('Error updating dashboard:', error);
        }
    }

    animateNumber(elementId, targetValue) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const currentValue = parseInt(element.textContent) || 0;
        const increment = (targetValue - currentValue) / 20;
        let current = currentValue;

        const timer = setInterval(() => {
            current += increment;
            if ((increment > 0 && current >= targetValue) || (increment < 0 && current <= targetValue)) {
                element.textContent = targetValue;
                clearInterval(timer);
            } else {
                element.textContent = Math.floor(current);
            }
        }, 50);
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <div class="flex items-center">
                <i class="fas fa-${this.getNotificationIcon(type)} mr-2"></i>
                <span>${message}</span>
            </div>
        `;

        document.body.appendChild(notification);

        // Show notification
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);

        // Remove notification after 5 seconds
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 5000);

        this.notifications.push(notification);
    }

    getNotificationIcon(type) {
        switch (type) {
            case 'success': return 'check-circle';
            case 'error': return 'exclamation-triangle';
            case 'warning': return 'exclamation-circle';
            default: return 'info-circle';
        }
    }

    // Utility function for smooth scrolling
    scrollToSection(sectionId) {
        const element = document.getElementById(sectionId);
        if (element) {
            element.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    }
}

// Initialize the UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.cerebralGuardUI = new CerebralGuardUI();
});

// Make functions globally available
window.loadSampleEmail = function() {
    if (window.cerebralGuardUI) {
        window.cerebralGuardUI.loadSampleEmail();
    }
};

window.scrollToSection = function(sectionId) {
    if (window.cerebralGuardUI) {
        window.cerebralGuardUI.scrollToSection(sectionId);
    }
}; 