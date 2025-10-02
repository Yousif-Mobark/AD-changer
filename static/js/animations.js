/**
 * AD Password Changer - Dark Theme Animations
 * Sponsored by Digital Transformation
 * Created: October 2025
 */

// Particle animation system for background effects
document.addEventListener('DOMContentLoaded', function() {
    // Create particle container if it doesn't exist
    if (!document.querySelector('.particles')) {
        const particleContainer = document.createElement('div');
        particleContainer.className = 'particles';
        document.body.appendChild(particleContainer);
        
        // Create particles
        for (let i = 0; i < 30; i++) {
            createParticle();
        }
    }
    
    // Apply entrance animations to main content
    animateContent();
});

// Create a floating particle
function createParticle() {
    const particles = document.querySelector('.particles');
    const particle = document.createElement('div');
    
    // Random position, size and animation duration
    const size = Math.random() * 10 + 5;
    const posX = Math.random() * 100;
    const posY = Math.random() * 100;
    const duration = Math.random() * 20 + 10;
    const delay = Math.random() * 5;
    const opacity = Math.random() * 0.5 + 0.1;
    
    // Apply styles
    particle.className = 'particle';
    particle.style.width = `${size}px`;
    particle.style.height = `${size}px`;
    particle.style.left = `${posX}%`;
    particle.style.top = `${posY}%`;
    particle.style.opacity = opacity;
    particle.style.animationDuration = `${duration}s`;
    particle.style.animationDelay = `${delay}s`;
    
    particles.appendChild(particle);
    
    // Remove particle after animation ends (duration + delay)
    setTimeout(() => {
        particle.remove();
        createParticle(); // Create a new one to replace it
    }, (duration + delay) * 1000);
}

// Animate main content with staggered entrance
function animateContent() {
    const elements = document.querySelectorAll('.animate-in');
    
    elements.forEach((el, index) => {
        setTimeout(() => {
            el.style.opacity = '1';
            el.style.transform = 'translateY(0)';
        }, 100 * index);
    });
}

// Apply typing animation to specified elements
function typeText(element, text, speed = 50) {
    let i = 0;
    element.textContent = '';
    
    function type() {
        if (i < text.length) {
            element.textContent += text.charAt(i);
            i++;
            setTimeout(type, speed);
        }
    }
    
    type();
}