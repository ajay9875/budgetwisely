document.addEventListener("DOMContentLoaded", function () {
    {% if budgets %}
    const ctx = document.getElementById("budgetChart").getContext("2d");
    
    const budgetData = {{ budgets | tojson }};
    const months = budgetData.map(budget => budget.month_name);
    const incomeData = budgetData.map(budget => budget.monthly_income);
    const expensesData = budgetData.map(budget => budget.total_expenses);
    const savingsData = budgetData.map(budget => budget.savings);

    new Chart(ctx, {
        type: "bar",
        data: {
            labels: months,
            datasets: [
                {
                    label: "Income",
                    data: incomeData,
                    backgroundColor: "rgba(46, 204, 113, 0.7)",
                    borderColor: "rgba(46, 204, 113, 1)",
                    borderWidth: 1
                },
                {
                    label: "Expenses",
                    data: expensesData,
                    backgroundColor: "rgba(231, 76, 60, 0.7)",
                    borderColor: "rgba(231, 76, 60, 1)",
                    borderWidth: 1
                },
                {
                    label: "Savings",
                    data: savingsData,
                    backgroundColor: savingsData.map(value => 
                        value < 0 ? "rgba(231, 76, 60, 0.7)" : "rgba(52, 152, 219, 0.7)"),
                    borderColor: savingsData.map(value => 
                        value < 0 ? "rgba(231, 76, 60, 1)" : "rgba(52, 152, 219, 1)"),
                    borderWidth: 1,
                    type: 'bar'
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Monthly Budget Comparison',
                    font: {
                        size: 16
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            label += '₹' + context.raw.toFixed(2);
                            return label;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: false,
                    ticks: {
                        callback: function(value) {
                            return '₹' + value;
                        }
                    }
                }
            }
        }
    });
    {% endif %}
});
