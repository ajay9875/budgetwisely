function displaydetails(){
    let details = document.getElementById('profile-details');
    if (details.style.display ==='none' || details.style.display ==='' ){
        details.style.display = 'block';
    }
    else{
        details.style.display = 'none';
    }
}

// Toggle Hamburger Menu
function toggleMobileNav() {
    const navLinks = document.getElementById('nav-links');
    navLinks.classList.toggle('active');
}

// Close menus when clicking outside
document.addEventListener('click', function (event) {
    const navLinks = document.getElementById('nav-links');
    const hamburgerBtn = document.querySelector('.hamburger-btn');
    const profileDetails = document.getElementById('profile-details');
    const profileBtn = document.querySelector('.profile-btn');

    // Close Hamburger menu if open & click was outside
    if (navLinks && navLinks.classList.contains('active')) {
        if (!navLinks.contains(event.target) && !hamburgerBtn.contains(event.target)) {
            navLinks.classList.remove('active');
        }
    }

    // Close Profile dropdown if open & click was outside
    if (profileDetails && profileDetails.classList.contains('show')) {
        if (!profileDetails.contains(event.target) && !profileBtn.contains(event.target)) {
            profileDetails.classList.remove('show');
        }
    }
});
