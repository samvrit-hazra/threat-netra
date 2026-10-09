/**
 * Threat Netra - Defense Intelligence UI Interactions
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Header scroll detection
    const navbar = document.getElementById('topNavbar');
    if (navbar) {
        const handleScroll = () => {
            if (window.scrollY > 20) {
                navbar.classList.add('scrolled');
            } else {
                navbar.classList.remove('scrolled');
            }
        };
        window.addEventListener('scroll', handleScroll, { passive: true });
        handleScroll();
    }

    // 2. Animate stat numbers count up once when scrolled into view
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    
    if (!prefersReducedMotion) {
        const stats = document.querySelectorAll('.stat-num');
        
        if (stats.length > 0 && 'IntersectionObserver' in window) {
            const observer = new IntersectionObserver((entries, obs) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const el = entry.target;
                        const targetText = el.textContent.trim();
                        const targetNum = parseInt(targetText, 10);
                        
                        if (!isNaN(targetNum) && targetNum > 0) {
                            let current = 0;
                            const duration = 800; // ms
                            const stepTime = Math.max(Math.floor(duration / targetNum), 20);
                            const increment = Math.ceil(targetNum / (duration / stepTime));
                            
                            const timer = setInterval(() => {
                                current += increment;
                                if (current >= targetNum) {
                                    el.textContent = targetNum;
                                    clearInterval(timer);
                                } else {
                                    el.textContent = current;
                                }
                            }, stepTime);
                        }
                        obs.unobserve(el);
                    }
                });
            }, { threshold: 0.3 });

            stats.forEach(s => observer.observe(s));
        }
    }
});
