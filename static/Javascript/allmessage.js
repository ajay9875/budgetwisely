document.addEventListener("DOMContentLoaded", function () {
    setTimeout(function () {
        let messages = document.querySelectorAll('.message');
        messages.forEach(function (message) {
            message.classList.add("fade-out"); // Add fade-out animation
            setTimeout(() => message.style.display = "none", 1000); // Hide after fade
        });
    }, 5000);  // Messages disappear after 5 seconds

    function toggleExpenseForm(formId) {
    const formRow = document.getElementById(formId);
    if (formRow) {
        if (formRow.style.display === "none" || formRow.style.display === "") {
            formRow.style.display = "table-row";
        } else {
            formRow.style.display = "none";
        }
    }
}
});

// 2. Global Toggle Function (accessible by onclick="...")
function toggleExpenseForm(formId) {
    const formRow = document.getElementById(formId);
    if (formRow) {
        if (formRow.style.display === "none" || formRow.style.display === "") {
            formRow.style.display = "table-row";
        } else {
            formRow.style.display = "none";
        }
    }
}

// 3. Confirm Delete Function
function confirmDeleteExpense(expenseId, monthName) {
    if (confirm("Delete this individual expense item?")) {
        showLoadingSpinner('Removing item...');
        
        // Form submission fallback for expense removal
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/delete_expense';

        const expInput = document.createElement('input');
        expInput.type = 'hidden';
        expInput.name = 'expense_id';
        expInput.value = expenseId;
        form.appendChild(expInput);

        const monthInput = document.createElement('input');
        monthInput.type = 'hidden';
        monthInput.name = 'month_name';
        monthInput.value = monthName;
        form.appendChild(monthInput);

        document.body.appendChild(form);
        form.submit();
    }
}

