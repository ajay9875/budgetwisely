function toggleDarkMode() {
    const body = document.body;
    body.classList.toggle('dark-mode');

    // Store user preference in localStorage
    if (body.classList.contains('dark-mode')) {
        localStorage.setItem('theme', 'dark');
    } else {
        localStorage.setItem('theme', 'light');
    }
}

// Load theme preference from localStorage
document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem('theme') === 'dark') {
        document.body.classList.add('dark-mode');
    }
});