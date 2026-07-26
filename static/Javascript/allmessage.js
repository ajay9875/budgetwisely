document.addEventListener("DOMContentLoaded", function () {
    setTimeout(function () {
        let messages = document.querySelectorAll('.message');
        messages.forEach(function (message) {
            message.classList.add("fade-out"); // Add fade-out animation
            setTimeout(() => message.style.display = "none", 1000); // Hide after fade
        });
    }, 5000);  // Messages disappear after 5 seconds
});


